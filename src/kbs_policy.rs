use std::fs;
use anyhow::{Result};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SingleShotCommandLineModeConfig {
    pub allowed_cmd: Vec<String>,
    pub allowed_dir: Vec<String>,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct PrivilegedUserConfig {
    pub enable_terminal: bool,
    pub enable_single_shot_command_line_mode: bool,
    pub single_shot_command_line_mode_configs : SingleShotCommandLineModeConfig,
    pub exec_result_encryption: bool,
    pub enable_container_logs_encryption:bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct UnprivilegedUserConfig {
    pub enable_terminal: bool,
    pub enable_single_shot_command_line_mode: bool,
    pub single_shot_command_line_mode_configs : SingleShotCommandLineModeConfig,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct EnvCmdBasedSecrets {
    pub env_variables: Vec<String>,
    pub cmd_arg: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct KbsPolicy {
    pub enable_policy_updata: bool,
    pub privileged_user_config: PrivilegedUserConfig,
    pub unprivileged_user_config:  UnprivilegedUserConfig,
    pub privileged_user_key_slice: String,
}



impl KbsPolicy {

    // if the config file exist, load file and return true; otherwise return false
    pub fn load(&mut self, policy_paht: &str) -> Result<()> {

        let contents = match fs::read_to_string(policy_paht) {
            Ok(c) => c,
            Err(e) => return Err(anyhow::Error::msg(format!("KbsPolicy Load fs::read_to_string(policy_paht) failed  error {:?}", e))),
        };

        let config = serde_json::from_str(&contents).expect("KbsPolicy Load policy wrong format");
        *self = config;
        return Ok(());
    }
}


