#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use eth_trie::MemoryDB;
    use eth_trie::{EthTrie, Trie, TrieError};

    #[test]
    fn test_trie() -> Result<(), TrieError> {
        let memdb = Arc::new(MemoryDB::new(true));

        let key = b"test-key";
        let value = b"test-value";

        let root = {
            let mut trie = EthTrie::new(Arc::clone(&memdb));
            trie.insert(key, value)?;

            let v = trie.get(key)?;
            assert_eq!(Some(value.to_vec()), v);
            trie.root_hash()?
        };
        assert_eq!(root.as_bytes(), b"\x0ee/\xd2Y,\x8aS}\xcf|0\x85L\xb2\x87\xea\xabt\x0c\x16\xd9G\x0c\xa3\xe0S\xf4\x9b}\xe3g");

        let mut trie = EthTrie::from(Arc::clone(&memdb), root)?;

        let exists = trie.contains(key)?;
        assert_eq!(exists, true);

        let removed = trie.remove(key)?;
        assert_eq!(removed, true);

        // Back to the empty key after removing the only key
        let new_root = trie.root_hash()?;
        assert_eq!(new_root.as_bytes(), b"V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!");
        Ok(())
    }
}
