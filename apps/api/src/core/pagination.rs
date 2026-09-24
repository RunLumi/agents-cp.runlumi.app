use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::CoreError;

/// Opaque non-empty cursor. Its contents are never parsed or normalized here.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct Cursor(String);

impl Cursor {
    pub fn new(value: impl Into<String>) -> Result<Self, CoreError> {
        let value = value.into();
        if value.is_empty() {
            return Err(CoreError::InvalidCursor);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cursor([opaque])")
    }
}

impl<'de> Deserialize<'de> for Cursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Frozen cursor page response shape.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

impl<T> Page<T> {
    pub fn new(
        items: Vec<T>,
        next_cursor: Option<Cursor>,
        has_more: bool,
    ) -> Result<Self, CoreError> {
        if has_more != next_cursor.is_some() {
            return Err(CoreError::InconsistentPageCursor);
        }
        Ok(Self {
            items,
            next_cursor,
            has_more,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn page_uses_frozen_field_names_and_keeps_cursor_opaque() {
        let page = Page::new(
            vec!["row"],
            Some(Cursor::new("opaque+/token==").unwrap()),
            true,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(page).unwrap(),
            json!({
                "items": ["row"],
                "next_cursor": "opaque+/token==",
                "has_more": true
            })
        );
    }

    #[test]
    fn empty_cursor_is_a_typed_error_on_input_and_deserialization() {
        assert_eq!(Cursor::new(""), Err(CoreError::InvalidCursor));
        assert!(serde_json::from_str::<Cursor>("\"\"").is_err());
        assert_eq!(
            format!("{:?}", Cursor::new("opaque-token").unwrap()),
            "Cursor([opaque])"
        );
    }

    #[test]
    fn page_requires_a_cursor_when_more_items_exist() {
        assert!(matches!(
            Page::<()>::new(Vec::new(), None, true),
            Err(CoreError::InconsistentPageCursor)
        ));
        assert!(Page::<()>::new(Vec::new(), None, false).is_ok());
    }
}
