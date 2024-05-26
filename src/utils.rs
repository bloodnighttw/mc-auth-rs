use std::time::Duration;
use chrono::{DateTime, Local};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[derive(Clone,Deserialize,Serialize,Debug,PartialEq)]
pub struct TimeSensitiveData<T> where T: TimeSensitiveTrait {
    pub(crate) data: T,
    /// The time when the data was created.
    #[serde(deserialize_with = "to_time",serialize_with = "to_str")]
    time:DateTime<Local>,
}

pub trait TimeSensitiveTrait {
    fn get_duration(&self) -> Duration;
}

impl<T> TimeSensitiveData<T> where T: TimeSensitiveTrait {
    pub fn new(data: T) -> Self {
        Self {
            data,
            time: Local::now(),
        }
    }

    pub fn is_vaild(&self) -> bool {
        let duration = (Local::now() - self.time).to_std().expect("Failed to convert chrono::Duration to std::Duration");
        duration < self.data.get_duration()
    }

}

fn to_time<'de, D: Deserializer<'de>>(deserializer: D) -> Result<DateTime<Local>, D::Error> {
    Ok(match Value::deserialize(deserializer)? {
        Value::String(num) =>{
            let t = num.as_str();
            let datetime = DateTime::parse_from_rfc3339(t).expect("Failed to parse time");
            datetime.with_timezone(&Local)
        } ,
        _ => return Err(de::Error::custom("wrong type"))
    })
}

fn to_str<S>(x: &DateTime<Local>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    s.serialize_str(x.to_rfc3339().as_str())
}