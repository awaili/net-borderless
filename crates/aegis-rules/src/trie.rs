//! 域名 trie：DOMAIN / DOMAIN-SUFFIX 的批量匹配。
//!
//! M0 性能门（docs/02 §8）：10 万条域名规则下 p99 查询 < 50µs。
//! 顺序扫描对每条连接是 O(规则数)；trie 把匹配降到 O(域名标签数)。
//!
//! 结构：按**反转标签序列**分支（`netflix.com` → `com → netflix`）。
//! 后缀匹配的天然属性：查询 `www.netflix.com`（反转 [com, netflix, www]）
//! 沿 trie 走，途中任意节点的 `suffix` 终态都是命中——继续走到头可同时
//! 覆盖更深的后缀规则（如 `www.netflix.com` 本身也是 DOMAIN-SUFFIX 规则）。
//! 精确匹配（DOMAIN）只在标签恰好消费完时看 `exact` 终态。
//!
//! 所有命中取**最小规则下标**，与 CompiledRules 的首中语义对齐：
//! 引擎拿 trie 结果与顺序扫描结果按下标取 min，行为与纯顺序扫描严格等价。

use std::collections::HashMap;

#[derive(Debug, Default)]
pub(crate) struct DomainTrie {
    /// 分支：key = 小写标签
    children: HashMap<Box<str>, Box<DomainTrie>>,
    /// DOMAIN-SUFFIX 终态：本节点为后缀末端（命中含所有后代）
    suffix: Option<usize>,
    /// DOMAIN 终态：整域恰好消费完时命中
    exact: Option<usize>,
}

impl DomainTrie {
    /// 插入 DOMAIN-SUFFIX 规则（`idx` 为规则下标；重复插入保留较小值）。
    pub(crate) fn insert_suffix(&mut self, domain: &str, idx: usize) {
        let node = self.walk_or_create(domain);
        node.suffix = node.suffix.keep_min(idx);
    }

    /// 插入 DOMAIN 精确规则。
    pub(crate) fn insert_exact(&mut self, domain: &str, idx: usize) {
        let node = self.walk_or_create(domain);
        node.exact = node.exact.keep_min(idx);
    }

    /// 沿反转标签走到（必要时创建）末端节点。空标签跳过（`a..b` 类畸形输入）。
    fn walk_or_create(&mut self, domain: &str) -> &mut DomainTrie {
        let mut node = self;
        for label in domain.rsplit('.') {
            if label.is_empty() {
                continue;
            }
            node = node
                .children
                .entry(label.to_ascii_lowercase().into_boxed_str())
                .or_default();
        }
        node
    }

    /// 查询：返回所有命中规则的最小下标（`None` = 无命中）。
    /// 插入侧标签已小写，这里统一小写化查询域（大小写不敏感是 DNS 天然属性）。
    pub(crate) fn lookup(&self, domain: &str) -> Option<usize> {
        let domain = domain.to_ascii_lowercase();
        let mut best: Option<usize> = None;
        let mut node = self;
        let mut consumed_all = true;
        for label in domain.rsplit('.') {
            let Some(child) = node.children.get(label) else {
                consumed_all = false;
                break;
            };
            node = child;
            if let Some(i) = node.suffix {
                best = best.keep_min(i);
            }
        }
        if consumed_all {
            if let Some(i) = node.exact {
                best = best.keep_min(i);
            }
        }
        best
    }
}

/// Option<usize> 保小合并（trie 终态取最小规则下标用）。
trait KeepMin {
    fn keep_min(self, idx: usize) -> Option<usize>;
}
impl KeepMin for Option<usize> {
    fn keep_min(self, idx: usize) -> Option<usize> {
        match self {
            Some(existing) => Some(existing.min(idx)),
            None => Some(idx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_and_exact_precedence() {
        let mut t = DomainTrie::default();
        t.insert_suffix("netflix.com", 5);
        t.insert_suffix("www.netflix.com", 2); // 更深但下标更小
        t.insert_exact("netflix.com", 1); // 精确规则下标最小
        assert_eq!(t.lookup("netflix.com"), Some(1));
        assert_eq!(t.lookup("www.netflix.com"), Some(2)); // 途中 5，终点无 2 的后缀
        assert_eq!(t.lookup("a.www.netflix.com"), Some(2));
        assert_eq!(t.lookup("mynetflix.com"), None);
        assert_eq!(t.lookup("netflix.com.evil.org"), None);
        assert_eq!(t.lookup("notflix.com"), None);
    }

    #[test]
    fn case_insensitive_and_labels() {
        let mut t = DomainTrie::default();
        t.insert_suffix("Example.COM", 0);
        t.insert_exact("Api.Example.com", 1);
        assert_eq!(t.lookup("WWW.EXAMPLE.COM"), Some(0));
        assert_eq!(t.lookup("x.y.example.com"), Some(0));
        assert_eq!(t.lookup("api.example.com"), Some(0)); // 精确 1 vs 后缀 0 → 0
                                                          // 单标签后缀
        let mut t2 = DomainTrie::default();
        t2.insert_suffix("com", 3);
        assert_eq!(t2.lookup("anything.com"), Some(3));
        assert_eq!(t2.lookup("anything.net"), None);
    }
}
