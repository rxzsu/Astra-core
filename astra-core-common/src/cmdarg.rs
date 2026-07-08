/// Command-line argument type that can accumulate multiple values.
/// Go equivalent: `common/cmdarg.Arg` — used for accumulating -c/--config flags.
#[derive(Debug, Clone, Default)]
pub struct Arg {
    values: Vec<String>,
}

impl Arg {
    pub fn new() -> Self {
        Arg { values: Vec::new() }
    }

    pub fn push(&mut self, val: String) {
        self.values.push(val);
    }

    pub fn extend(&mut self, vals: Vec<String>) {
        self.values.extend(vals);
    }

    pub fn get(&self) -> &[String] {
        &self.values
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.values.iter()
    }
}

impl IntoIterator for Arg {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

impl From<Vec<String>> for Arg {
    fn from(v: Vec<String>) -> Self {
        Arg { values: v }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arg_accumulate() {
        let mut arg = Arg::new();
        assert!(arg.is_empty());
        arg.push("config1.json".into());
        arg.push("config2.json".into());
        assert_eq!(arg.len(), 2);
        assert_eq!(arg.get()[0], "config1.json");
    }

    #[test]
    fn test_arg_iter() {
        let arg = Arg::from(vec!["a".into(), "b".into()]);
        let collected: Vec<String> = arg.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }
}
