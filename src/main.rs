mod encryption_utilities;
mod error;
mod hmac_untilities;
mod serialize;
mod kbs_policy;

extern crate strum;
// use core::slice::SlicePattern;
use std::ffi::OsString;
use clap::{Parser, Subcommand, ValueEnum};
use std::env;
use anyhow::{bail, Context, Result};
use futures::{StreamExt, TryStreamExt, channel::mpsc::Sender, SinkExt};
use k8s_openapi::{
    apimachinery::pkg::apis::meta::v1::Time,
    chrono::{Duration, Utc},
    api::core::v1::Pod,
};
use base64ct::{Base64, Encoding};
use kube::{
    api::{Api, DynamicObject, ListParams, Patch, PatchParams, ResourceExt, AttachedProcess, AttachParams, TerminalSize},
    core::GroupVersionKind,
    discovery::{ApiCapabilities, ApiResource, Discovery, Scope},
    runtime::{
        wait::{await_condition, conditions::is_deleted},
        watcher, WatchStreamExt,
    },
    Client,
};
use tracing::*;

use encryption_utilities::*;
use postcard::accumulator::{CobsAccumulator, FeedResult};
use hmac_untilities::*;

use serde;
use serde_json;
use std::fs;

#[macro_use]
extern crate serde_derive;

/// A kubectl like secure client
#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "git")]
#[command(about = "A fictional versioning CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {

    /// Convert the frontend policy to the (backend) policy used by qkernel
    /// Default file path is current dir
    #[command(arg_required_else_help = true)]
    PreparePolicy {
        policy_path: Option<String>,
    },
    /// Allocate a terminal inside a container
    /// This terminal is cross platform runable
    #[command(arg_required_else_help = true)]
    Terminal {
        pod_name: Option<String>,
        container_name: Option<String>,
    },
    /// Issue cmd to a container
    /// Example: ./secure-client issue-cmd nginx "ls -t /var"
    #[command(arg_required_else_help = true)]
    IssueCmd {
        pod_name: Option<String>,
        cmd: Option<String>,
    },
    /// Get resource from cluster (in default namespace)
    #[command(arg_required_else_help = true)]
    Get {
        /// The remote to clone
        #[arg(long, short, default_value_t = OutputMode::Pretty)]
        output: OutputMode,
        #[arg(long, short = 'l')]
        selector: Option<String>,
        #[arg(long, short)]
        namespace: Option<String>,
        #[arg(long, short = 'A')]
        all: bool,
        resource: Option<String>,
        name: Option<String>,
    },
    /// Edit a resource
    #[command(arg_required_else_help = true)]
    Edit {
        #[arg(long, short, default_value_t = OutputMode::Pretty)]
        output: OutputMode,
        #[arg(long, short = 'l')]
        selector: Option<String>,
        #[arg(long, short)]
        namespace: Option<String>,
        #[arg(long, short = 'A')]
        all: bool,
        resource: Option<String>,
        name: Option<String>,
    },
    /// Delete a resource
    #[command(arg_required_else_help = true)]
    Delete {
        #[arg(long, short, default_value_t = OutputMode::Pretty)]
        output: OutputMode,
        #[arg(long, short = 'l')]
        selector: Option<String>,
        #[arg(long, short)]
        namespace: Option<String>,
        #[arg(long, short = 'A')]
        all: bool,
        resource: Option<String>,
        name: Option<String>,

    },
    /// Watches a Kubernetes Resource for changes continuously
    #[command(arg_required_else_help = true)]
    Watch {
        #[arg(long, short, default_value_t = OutputMode::Pretty)]
        output: OutputMode,
        #[arg(long, short = 'l')]
        selector: Option<String>,
        #[arg(long, short)]
        namespace: Option<String>,
        #[arg(long, short = 'A')]
        all: bool,
        resource: Option<String>,
        name: Option<String>,
    },
    /// Apply a configuration to a resource by file name
    #[command(arg_required_else_help = true)]
    Apply{
        #[arg(long, short, default_value_t = OutputMode::Pretty)]
        output: OutputMode,
        #[arg(long, short)]
        file: Option<std::path::PathBuf>,
        #[arg(long, short = 'l')]
        selector: Option<String>,
        #[arg(long, short)]
        namespace: Option<String>,
        #[arg(long, short = 'A')]
        all: bool,
        resource: Option<String>,
        name: Option<String>,
    },
    /// Get logs of the first container in Pod
    #[command(arg_required_else_help = true)]
    Logs{
        /// Follow the log stream of the pod. Defaults to `false`.
        #[arg(long, short='f')]
        follow: Option<bool>,
        /// Pod name
        pod_name: Option<String>,
        /// Container name in Pod, by default, the log return the log of the first container in Pod
        container_name: Option<String>,
    },
    /// Update Exec policy using secure channel
    #[command(arg_required_else_help = true)]
    PolicyUpdate{
        /// Pod name
        pod_name: Option<String>,
        /// Path of policy.json,  the default path is current dir
        policy_path: Option<String>,

    },
    #[command(external_subcommand)]
    External(Vec<OsString>),
}

#[derive(Clone, PartialEq, Eq, clap::ValueEnum, Debug)]
enum OutputMode {
    Pretty,
    Yaml,
}

impl OutputMode {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Pretty => "pretty",
            Self::Yaml => "yaml",
        }
    }
}

impl std::fmt::Display for OutputMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(self.as_str())
    }
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
enum ColorWhen {
    Always,
    Auto,
    Never,
}

impl std::fmt::Display for ColorWhen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}

fn resolve_api_resource(discovery: &Discovery, name: &str) -> Option<(ApiResource, ApiCapabilities)> {
    // iterate through groups to find matching kind/plural names at recommended versions
    // and then take the minimal match by group.name (equivalent to sorting groups by group.name).
    // this is equivalent to kubectl's api group preference
    discovery
        .groups()
        .flat_map(|group| {
            group
                .resources_by_stability()
                .into_iter()
                .map(move |res| (group, res))
        })
        .filter(|(_, (res, _))| {
            // match on both resource name and kind name
            // ideally we should allow shortname matches as well
            name.eq_ignore_ascii_case(&res.kind) || name.eq_ignore_ascii_case(&res.plural)
        })
        .min_by_key(|(group, _res)| group.name())
        .map(|(_, res)| res)

}

fn dynamic_api(
    ar: ApiResource,
    caps: ApiCapabilities,
    client: Client,
    ns: &Option<String>,
    all: bool,
) -> Api<DynamicObject> {
    if caps.scope == Scope::Cluster || all {
        Api::all_with(client, &ar)
    } else if let Some(namespace) = ns {
        Api::namespaced_with(client, namespace, &ar)
    } else {
        Api::default_namespaced_with(client, &ar)
    }
}


fn format_creation_since(time: Option<Time>) -> String {
    format_duration(Utc::now().signed_duration_since(time.unwrap().0))
}
fn format_duration(dur: Duration) -> String {
    match (dur.num_days(), dur.num_hours(), dur.num_minutes()) {
        (days, _, _) if days > 0 => format!("{days}d"),
        (_, hours, _) if hours > 0 => format!("{hours}h"),
        (_, _, mins) => format!("{mins}m"),
    }
}

pub fn multidoc_deserialize(data: &str) -> Result<Vec<serde_yaml::Value>> {
    use serde::Deserialize;
    let mut docs = vec![];
    for de in serde_yaml::Deserializer::from_str(data) {
        docs.push(serde_yaml::Value::deserialize(de)?);
    }
    Ok(docs)
}




struct App {
    pub output: OutputMode,
    pub file: Option<std::path::PathBuf>,
    pub selector: Option<String>,
    pub namespace: Option<String>,
    pub all: bool,
    pub resource: Option<String>,
    pub name: Option<String>,
}

fn prepare_api_object_lp (app: &App, discovery: &Discovery, client: Client) -> (Option<Api<DynamicObject>>, Option<ListParams>) {


    let res = resolve_api_resource(&discovery, app.resource.as_ref().unwrap().as_str())
    .with_context(|| format!("resource {:?} not found in cluster", app.resource));

    let ar;
    let caps;
    if res.is_ok() {
        (ar, caps) = res.unwrap();
    } else {
        return (None, None);
    }

    let mut lp = ListParams::default();
    if let Some(label) = &app.selector {
        lp = lp.labels(label);
    }
    let api = dynamic_api(ar, caps, client, &app.namespace, app.all);

    (Some(api), Some(lp))
}

impl App {
    fn new (output: OutputMode, file: Option<std::path::PathBuf>, selector: Option<String>, namespace: Option<String>,  all: bool, resource: Option<String>, name: Option<String>) ->  App {

         App {
            output,
            file,
            selector,
            namespace,
            all,
            resource,
            name,
        }


    }

    async fn get(&self, api: Api<DynamicObject>, lp: ListParams) -> Result<()> {
        let mut result: Vec<_> = if let Some(n) = &self.name {
            vec![api.get(n).await?]
        } else {
            api.list(&lp).await?.items
        };
        result.iter_mut().for_each(|x| x.managed_fields_mut().clear()); // hide managed fields

        match self.output {
            OutputMode::Yaml => println!("{}", serde_yaml::to_string(&result)?),
            OutputMode::Pretty => {
                // Display style; size columns according to longest name
                let max_name = result.iter().map(|x| x.name_any().len() + 2).max().unwrap_or(63);
                println!("{0:<width$} {1:<20}", "NAME", "AGE", width = max_name);
                for inst in result {
                    let age = format_creation_since(inst.creation_timestamp());
                    println!("{0:<width$} {1:<20}", inst.name_any(), age, width = max_name);
                }
            }
        }
        Ok(())
    }

    async fn delete(&self, api: Api<DynamicObject>, lp: ListParams) -> Result<()> {
        if let Some(n) = &self.name {
            if let either::Either::Left(pdel) = api.delete(n, &Default::default()).await? {
                // await delete before returning
                await_condition(api, n, is_deleted(&pdel.uid().unwrap())).await?;
            }
        } else {
            api.delete_collection(&Default::default(), &lp).await?;
        }
        Ok(())
    }



    async fn watch(&self, api: Api<DynamicObject>, mut lp: ListParams) -> Result<()> {
        if let Some(n) = &self.name {
            lp = lp.fields(&format!("metadata.name={n}"));
        }
        // present a dumb table for it for now. kubectl does not do this anymore.
        let mut stream = watcher(api, lp).applied_objects().boxed();
        println!("{0:<width$} {1:<20}", "NAME", "AGE", width = 63);
        while let Some(inst) = stream.try_next().await? {
            let age = format_creation_since(inst.creation_timestamp());
            println!("{0:<width$} {1:<20}", inst.name_any(), age, width = 63);
        }
        Ok(())
    }

    async fn edit(&self, api: Api<DynamicObject>) -> Result<()> {
        if let Some(n) = &self.name {
            let mut orig = api.get(n).await?;
            orig.managed_fields_mut().clear(); // hide managed fields
            let input = serde_yaml::to_string(&orig)?;
            debug!("opening {} in {:?}", orig.name_any(), edit::get_editor());
            let edited = edit::edit(&input)?;
            if edited != input {
                info!("updating changed object {}", orig.name_any());
                let data: DynamicObject = serde_yaml::from_str(&edited)?;
                // NB: simplified kubectl constructs a merge-patch of differences
                api.replace(n, &Default::default(), &data).await?;
            }
        } else {
            warn!("need a name to edit");
        }
        Ok(())
    }

    async fn apply(&self, client: Client, discovery: &Discovery) -> Result<()> {
        let ssapply = PatchParams::apply("kubectl-light").force();
        let pth = self.file.clone().expect("apply needs a -f file supplied");
        let yaml =
            std::fs::read_to_string(&pth).with_context(|| format!("Failed to read {}", pth.display()))?;
        for doc in multidoc_deserialize(&yaml)? {
            let obj: DynamicObject = serde_yaml::from_value(doc)?;
            let gvk = if let Some(tm) = &obj.types {
                GroupVersionKind::try_from(tm)?
            } else {
                bail!("cannot apply object without valid TypeMeta {:?}", obj);
            };
            let name = obj.name_any();
            if let Some((ar, caps)) = discovery.resolve_gvk(&gvk) {
                let api = dynamic_api(ar, caps, client.clone(), &self.namespace, false);
                trace!("Applying {}: \n{}", gvk.kind, serde_yaml::to_string(&obj)?);
                let data: serde_json::Value = serde_json::to_value(&obj)?;
                let _r = api.patch(&name, &ssapply, &Patch::Apply(data)).await?;
                info!("applied {} {}", gvk.kind, name);
            } else {
                warn!("Cannot apply document for unknown {:?}", gvk);
            }
        }
        Ok(())
    }
}


async fn get_output (key_manager:KeyManager, mut attached: AttachedProcess) -> Result<()> {
    let mut stdout = tokio_util::io::ReaderStream::new(attached.stdout().unwrap());
    // let out = stdout.
    let mut stream_contents = Vec::new();

    while let Some(chunk) = stdout.next().await {
        stream_contents.extend_from_slice(&chunk?);
    }

    let plain_text = get_cmd_res_in_plaintext(&key_manager.encryption_key, &mut stream_contents).unwrap();

    let str = String::from_utf8(plain_text);
    
    if str.is_err() == true {
        println!("{:?}", str);

    }else {
        println!("{}", str.unwrap());
    }
    Ok(())
}

#[cfg(unix)] use tokio::signal;
use tokio::{io::AsyncWriteExt, select};

#[cfg(unix)]
// Send the new terminal size to channel when it change
async fn handle_terminal_size(mut channel: Sender<TerminalSize>) -> Result<(), anyhow::Error> {
    let (width, height) = crossterm::terminal::size()?;
    channel.send(TerminalSize { height, width }).await?;

    // create a stream to catch SIGWINCH signal
    let mut sig = signal::unix::signal(signal::unix::SignalKind::window_change())?;
    loop {
        if (sig.recv().await).is_none() {
            return Ok(());
        }

        let (width, height) = crossterm::terminal::size()?;
        channel.send(TerminalSize { height, width }).await?;
    }
}

#[cfg(windows)]
// We don't support window for terminal size change, we only send the initial size
async fn handle_terminal_size(mut channel: Sender<TerminalSize>) -> Result<(), anyhow::Error> {
    let (width, height) = crossterm::terminal::size()?;
    channel.send(TerminalSize { height, width }).await?;
    let mut ctrl_c = tokio::signal::windows::ctrl_c()?;
    ctrl_c.recv().await;
    Ok(())
}

//Todo: allocate terminal in _container_name contianer
async fn termianl(pod_name: String, container_name : Option<String>, pods: Api<Pod>, key_manager:KeyManager, s:&mut Session) -> anyhow::Result<()> {

    // Here we we put the terminal in 'raw' mode to directly get the input from the user and sending it to the server and getting the result from the server to display directly.
    // We also watch for change in your terminal size and send it to the server so that application that use the size work properly.
    crossterm::terminal::enable_raw_mode()?;

    let cmd = "sh".to_string();
    let privileged_req = prepare_priviled_exec_cmd(cmd, &key_manager.key_slice, &key_manager.encryption_key, s);

    let mut attached: AttachedProcess = pods
    .exec(
        &pod_name,
        privileged_req,
        &AttachParams{
            container: container_name,
            ..Default::default()
        }.stdin(true).tty(true).stderr(false),
    )
    .await?;

    s.increas_counter();
    // stdin, stdout represent the standard io on client side
    let mut stdin = tokio_util::io::ReaderStream::new(tokio::io::stdin());
    let mut stdout = tokio::io::stdout();

    // output, input represent the standard io on qvisor side
    let mut output = tokio_util::io::ReaderStream::new(attached.stdout().unwrap());
    let mut input = attached.stdin().unwrap();

    let term_tx = attached.terminal_size().unwrap();

    let mut handle_terminal_size_handle = tokio::spawn(handle_terminal_size(term_tx));

    // let mut cobs_stdout_buf: CobsAccumulator<256> = CobsAccumulator::new();
    let mut i = 0;
    loop {
        select! {
            message = stdin.next() => {
                match message {
                    Some(Ok(message)) => {
                        // let byte_u8 = message.to_vec();
                        // let str_text = String::from_utf8(byte_u8).unwrap();
                        // println!("stdin {}, {}", str_text, i);
                        input.write(&message).await?;
                    }
                    error => {
                        println!("got error from local stdin {:?}", error);
                        break;
                    },
                }
            },
            message = output.next() => {

                match message {
                    Some(Ok(message)) => {
                        // let byte_u8 = message.to_vec();

                        // let window = byte_u8.as_slice();
    
                        // let frames = Vec::<IoFrame>::new();
                        
                        // let a = from_bytes_cobs::<IoFrame>(&mut byte_u8).unwrap();
                        // frames.push(a);
                        // 'cobs: while !byte_u8.is_empty() {
                        //     window = match cobs_stdout_buf.feed::<IoFrame>(&window) {
                        //         FeedResult::Consumed => break 'cobs,
                        //         FeedResult::OverFull(new_wind) => new_wind,
                        //         FeedResult::DeserError(new_wind) => new_wind,
                        //         FeedResult::Success { data, remaining } => {
                        //             // Do something with `data: MyData` here.
                    
                        //             // dbg!(data);
                        //             frames.push(data);
                        //             remaining
                        //         }
                        //     };
                        // }


                        // stdout.write(&message).await?;
                        // stdout.flush().await?;
                        // if frames.len() == 0 {
                        //     continue;
                        // }
                        // assert_eq!(frames.len(),  1);
                        // println!("len {:?}", frames.len());
                        // let plain_text = get_decoded_payloads(&key_manager.key, frames).unwrap();

                        // let str_text = String::from_utf8(byte_u8).unwrap();
                        // let str_trimed = str_text.trim();
                        // let str_trimed_byte = str_trimed.as_bytes();

                        // print!("stdout {:?}, {}", str_text, i);
                        stdout.write(&message).await?;
                        stdout.flush().await?;

                        i = i +1;
                    },
                    error => {
                        println!("got error from pod stdout: {:?}, termianl allocation req is rejected", error);
                        break
                    },
                }
            },
            result = &mut handle_terminal_size_handle => {
                match result {
                    Ok(_) => println!("End of terminal size stream"),
                    Err(e) => println!("Error getting terminal size: {e:?}")
                }
            },
        };
    }
    crossterm::terminal::disable_raw_mode()?;
    
    
    Ok(())

}


const SESSION_FILE_PATH: &str = "session.json";
impl Session {
    pub fn load() -> Result<Session, serialize::SerializeError> {
        serialize::deserialize(SESSION_FILE_PATH)
    }

    pub fn save(&self) -> Result<(), serialize::SerializeError> {
        serialize::serialize(self, SESSION_FILE_PATH)
    }

    pub fn increas_counter(&mut self) -> () {
        self.counter = self.counter + 1;
        self.save().unwrap();
    }

    pub fn delete(&self) -> () {
        if !fs::metadata(SESSION_FILE_PATH).is_ok() {
            return;
        }
        fs::remove_file("me.txt").expect("File delete failed");
    }


    pub async fn login_to_qkernel(key_manager: &KeyManager, pod_name: &String, pods: &Api<Pod>) ->  Result<Session> {

        let get_session_req = prepare_secure_vm_login_req(&key_manager.key_slice, &key_manager.encryption_key);

        println!("login_to_qkernel exec before");
        let attached = pods
        .exec(
            pod_name,
            get_session_req,
            &AttachParams::default().stderr(false),
        )
        .await?;

        println!("login_to_qkernel exec after");

        let s = parse_login_req_output(key_manager, attached).await?;

        Ok(s)
    }
}


async fn parse_login_req_output (key_manager: &KeyManager, mut attached: AttachedProcess) -> Result<Session> {
    let mut stdout = tokio_util::io::ReaderStream::new(attached.stdout().unwrap());
    // let out = stdout.
    let mut stream_contents = Vec::new();

    while let Some(chunk) = stdout.next().await {
        stream_contents.extend_from_slice(&chunk?);
    }

    let mut plain_text = get_cmd_res_in_plaintext(&key_manager.encryption_key, &mut stream_contents).unwrap();

    let session =  postcard::from_bytes::<Session>(&mut plain_text[..])?;

    println!("got session {:?}", session);
    
    Ok(session)
}


#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    let client = Client::try_default().await?;
    let discovery = Discovery::new(client.clone()).run().await?;
    let key_manager = KeyManager::init();

    match args.command {
        Commands::PreparePolicy {
            policy_path,
        } => {
            let policy_dir = if policy_path.is_some() {
                policy_path.unwrap()
            } else {
                let current_dir = env::current_dir().unwrap();
                
                let policy_path = format!("{}/policy.json", current_dir.to_str().unwrap());
                policy_path
            };

            let mut policy = kbs_policy::FrontEndKbsPolicy::default();
            policy.load(&policy_dir).unwrap();
            policy.get_back_end_policy().unwrap();
        }
        Commands::PolicyUpdate {
            pod_name,
            policy_path
        } => {
            const POLICYUPDATE_KEYWORD: &str = "PolicyUpdate ";

            println!("PolicyUpdate pod_name {:?}, policy_path {:?}", pod_name, policy_path);
            assert!(pod_name.is_some());

            let pod_name = pod_name.unwrap();
            let pods: Api<Pod> = Api::default_namespaced(client);

            let policy_dir = if policy_path.is_some() {
                policy_path.unwrap()
            } else {
                let current_dir = env::current_dir().unwrap();
                
                let policy_path = format!("{}/policy.json", current_dir.to_str().unwrap());
                policy_path
            };
            let mut policy = kbs_policy::FrontEndKbsPolicy::default();
            policy.load(&policy_dir).unwrap();
            let mut backend_policy = policy.get_back_end_policy().unwrap();
            backend_policy.syscall_interceptor_config.syscalls = Vec::new();
            let backend_policy_in_json_string = serde_json::to_string(&backend_policy).unwrap();

            let policy_in_base64_string = Base64::encode_string(&backend_policy_in_json_string.as_bytes());
            let mut update_cmd = POLICYUPDATE_KEYWORD.to_owned();
            update_cmd.push_str(&policy_in_base64_string);

            // println!("update_cmd {:?}, policy {:?}", update_cmd, policy);

            let mut s = match Session::load() {
                Ok(s) => s,
                Err(_) => {
                    println!("PolicyUpdate session dosen't exist, let's get one from qkernel");
                    let s = Session::login_to_qkernel(&key_manager, &pod_name, &pods).await.unwrap();
                    s.save().unwrap();
                    s
                }
            };

            let privileged_req = prepare_priviled_exec_cmd(update_cmd, &key_manager.key_slice, &key_manager.encryption_key, &mut s);
            // info!("PolicyUpdate privileged req {:?}", privileged_req);

            // let mut test_verify_privileged_exec_cmd = privileged_req.clone();
            // let verification_result = verify_privileged_exec_cmd(&mut test_verify_privileged_exec_cmd, &key_manager.key_slice, &key_manager.encryption_key).unwrap();
            // info!("PolicyUpdate verification_result {:?}", verification_result);

            let attached = pods.exec(
                &pod_name,
                privileged_req,
                &AttachParams::default().stderr(false),
            ).await?;

            s.increas_counter();
            get_output(key_manager, attached).await?;
        }
        Commands::Terminal {
            pod_name,
            container_name
        } => {

            println!("Terminal pod_name {:?}, container_name {:?}", pod_name, container_name);
            assert!(pod_name.is_some());

            let pod_name = pod_name.unwrap();

            let pods: Api<Pod> = Api::default_namespaced(client);
            let mut s = match Session::load() {
                Ok(s) => s,
                Err(_) => {
                    println!("session dosen't exist, let's get one from qkernel");
                    let s = Session::login_to_qkernel(&key_manager, &pod_name, &pods).await.unwrap();
                    s.save().unwrap();
                    s
                }
            };
            // println!("got session : {:?}", s);

            termianl(pod_name, container_name, pods, key_manager, &mut s).await?;

        },
        Commands::IssueCmd {
            pod_name,
            cmd
        } => {

            println!("pod_name {:?}, cmd {:?}", pod_name, cmd);
            assert!(pod_name.is_some());
            assert!(cmd.is_some());

            let cmd = cmd.unwrap();
            let pod_name = pod_name.unwrap();
            let pods: Api<Pod> = Api::default_namespaced(client);

            let mut s = match Session::load() {
                Ok(s) => s,
                Err(_) => {
                    println!("session dosen't exist, let's get one from qkernel");
                    let s = Session::login_to_qkernel(&key_manager, &pod_name, &pods).await.unwrap();
                    s.save().unwrap();
                    s
                }
            };
            // println!("got session : {:?}", s);

            // let mut login_req = prepare_secure_vm_login_req (&key_manager.key_slice, &key_manager.encryption_key);
            // let login_cmd = verify_privileged_exec_cmd(&mut login_req, &key_manager.key_slice, &key_manager.encryption_key).unwrap();
            // println!("login_cmd in qkenel req {:?}", login_cmd);
        
            let privileged_req = prepare_priviled_exec_cmd(cmd, &key_manager.key_slice, &key_manager.encryption_key, &mut s);
            // info!("privileged req {:?}", privileged_req);

            let mut test_verify_privileged_exec_cmd = privileged_req.clone();
            let verification_result = verify_privileged_exec_cmd(&mut test_verify_privileged_exec_cmd, &key_manager.key_slice, &key_manager.encryption_key).unwrap();
            // info!("verification_result {:?}", verification_result);

            let attached = pods
            .exec(
                &pod_name,
                privileged_req,
                &AttachParams::default().stderr(false),
            )
            .await?;

            s.increas_counter();
            get_output(key_manager, attached).await?;
        },
        Commands::Logs {
            pod_name,
            container_name,
            follow
        } => {
            // println!("kubectl logs pod: {:?}, container: {:?}, follow: {:?}", pod_name, container_name, follow);

            if pod_name.is_some() == true {
                let is_follow = if let Some(f) = follow  {
                    f 
                } else {
                    false
                };

                let pods: Api<Pod> = Api::default_namespaced(client);
                // println!("kubectl logs pod: {:?}, container: {:?}, follow: {:?}", pod_name, container_name, is_follow);
                let mut logs = pods
                .log_stream(
                    &pod_name.unwrap(), 
                    &kube::api::LogParams {
                        follow: is_follow,
                        // tail_lines: Some(1),
                        container: container_name,
                        timestamps:false,
                        // timestamps: false,
                        ..kube::api::LogParams::default()
                    }
                ).await?.boxed();
                // println!("1");

                let mut cobs_buf: CobsAccumulator<1024> = CobsAccumulator::new();
                
                while let Some(line) = logs.try_next().await? {

                    // println!("2");
                    let byte_u8 = line.to_vec();
                    if byte_u8.len() == 0 {
                        break;
                    }

                    let mut window = byte_u8.as_slice();

                    let mut  frames = Vec::<IoFrame>::new();

                    'cobs: while !byte_u8.is_empty() {
                        window = match cobs_buf.feed::<IoFrame>(&window) {
                            FeedResult::Consumed => break 'cobs,
                            FeedResult::OverFull(new_wind) => new_wind,
                            FeedResult::DeserError(new_wind) => new_wind,
                            FeedResult::Success { data, remaining } => {
                                // Do something with `data: MyData` here.
                
                                // dbg!(data);
                                frames.push(data);
                                remaining
                            }
                        };
                    }

                    // println!("len {:?}", frames.len());


                    let plain_text = get_decoded_payloads(&key_manager.encryption_key, frames).unwrap();


                    let text =  String::from_utf8_lossy(&plain_text);

                    println!("{}", text);
                }

            }
            return Ok(());
        },
        Commands::Get {
            output,
            resource,
            name,namespace, 
            all, 
            selector 
        } => {
            
            let app = App::new(output, None, selector, namespace, all, resource, name);
            //trace!("kubectl get {:?}, {:?} {output}", resource, name);
            if let Some(resource) = &app.resource {
                let (api, lp) = prepare_api_object_lp(&app, &discovery, client);

                if api.is_none() {
                    bail!("resource {:?} not found in cluster", resource);
                }

                app.get(api.unwrap(), lp.unwrap()).await?;
                return Ok(());
            }
            else {
                bail!("Missing get need");
            }

        }
        Commands:: Edit {
            output,
            resource,
            name,namespace, 
            all, 
            selector 
        } => {
            let app = App::new(output, None, selector, namespace, all, resource, name);
            //trace!("kubectl get {:?}, {:?} {output}", resource, name);
            if let Some(resource) = &app.resource {
                let (api, _) = prepare_api_object_lp(&app, &discovery, client);

                if api.is_none() {
                    bail!("resource {:?} not found in cluster", resource);
                }

                app.edit(api.unwrap()).await?;
                return Ok(());
            }
            else {
                bail!("Missing get need");
            }

        }
        Commands::Delete {
            output,
            resource,
            name,namespace, 
            all, 
            selector 
        } => {
            let app = App::new(output, None, selector, namespace, all, resource, name);
            //trace!("kubectl get {:?}, {:?} {output}", resource, name);
            if let Some(resource) = &app.resource {
                let (api, lp) = prepare_api_object_lp(&app, &discovery, client);

                if api.is_none() {
                    bail!("resource {:?} not found in cluster", resource);
                }

                app.delete(api.unwrap(), lp.unwrap()).await?;
                return Ok(());
            }
            else {
                bail!("Missing get need");
            }
            
        }
        Commands::Watch {
            output,
            resource,
            name,namespace, 
            all, 
            selector 
         } => {
            let app = App::new(output, None, selector, namespace, all, resource, name);
            //trace!("kubectl get {:?}, {:?} {output}", resource, name);
            if let Some(resource) = &app.resource {
                let (api, lp) = prepare_api_object_lp(&app, &discovery, client);

                if api.is_none() {
                    bail!("resource {:?} not found in cluster", resource);
                }

                app.watch(api.unwrap(), lp.unwrap()).await?;
                return Ok(());
            }
            else {
                bail!("Missing get need");
            }
        }
        Commands::Apply {
            output,
            resource,
            name,namespace, 
            all, 
            selector,
            file
        } => {
            let app = App::new(output, file, selector, namespace, all, resource, name);
            //trace!("kubectl get {:?}, {:?} {output}", resource, name);
  
            app.apply(client, &discovery).await?;
            
        }
        Commands::External(_args) => {
           return  Ok(());
        }


    }

    Ok(())

    // Continued program logic goes here...
}
