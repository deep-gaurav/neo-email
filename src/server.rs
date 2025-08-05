use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

use crate::controllers::on_auth::OnAuthController;
use crate::controllers::on_conn::OnConnController;
use crate::controllers::on_mail_cmd::OnMailCommandController;
use crate::controllers::on_rcpt::OnRCPTCommandController;
use crate::controllers::on_unknown_command::OnUnknownCommandController;
use crate::handle_connection::handle_connection_with_timeout;

use super::command::Commands;
use super::connection::SMTPConnection;
use super::connection::SMTPConnectionStatus;
use super::controllers::on_close::OnCloseController;
use super::controllers::on_email::OnEmailController;
use super::controllers::on_reset::OnResetController;

/// # SMTPServer
///
/// This struct is responsible for holding the SMTPServer configuration and state.
///
/// ## Example
///
/// ```rust
/// use neo_email::server::SMTPServer;
/// use std::net::SocketAddr;
///
/// #[derive(Debug, Clone, Default)]
/// pub struct ConnectionState {
///     pub authenticated: bool,
///     pub sender: Option<String>,
///     pub recipients: Vec<String>,
/// }
///
/// #[tokio::main]
/// async fn main() {
/// let addr = SocketAddr::from(([127, 0, 0, 1], 2526));
/// SMTPServer::<ConnectionState>::new()
///        // Set the number of workers to 1
///        .workers(1)
///        // Set the TLS acceptor
///        // .set_tls_acceptor(tokio_tls_acceptor)
///        // Set an controller to dispatch when an authentication is received
///        // .on_auth(OnAuthController::new(on_auth))
///        // Set an controller to dispatch when an email is received
///        // .on_email(OnEmailController::new(on_email))
///        // Set an controller to dispatch when a mail command is received, usually is to indicate the sender of the email
///        // .on_mail_cmd(OnMailCommandController::new(on_mail_cmd))
///        // Set an controller to dispatch when a rcpt command is received, usually is to indicate the recipient/s of the email
///        // .on_rcpt_cmd(OnRCPTCommandController::new(on_rcpt_cmd))
///        // .on_close(OnCloseController::new(on_close))
///        // .on_reset(OnResetController::new(on_reset))
///        // .on_unknown_cmd(OnUnknownCommandController::new(on_unknown_command))
///        // Bind the server to the address
///        .bind(addr)
///        .await
///        .unwrap()
///        // Run the server
///        .run()
///        .await;
/// }
/// ```
pub struct SMTPServer<B> 
where
    B: Default + Send + Sync + Clone,{
    /// # listener
    ///
    /// This field is responsible for holding the listener that will be used by the server.
    listener: Option<Arc<tokio::net::TcpListener>>,

    /// # threads_pool
    ///
    /// This field is responsible for holding the ThreadPool that will be used by the server.
    // threads_pool: Option<Arc<rayon::ThreadPool>>,
    /// # tls_acceptor
    ///
    /// This field is responsible for holding the TLS Acceptor that will be used by the server.
    tls_acceptor: Option<Arc<Mutex<tokio_native_tls::TlsAcceptor>>>,

    dns_resolver: Arc<Mutex<TokioAsyncResolver>>,

    config: Config<B>,
}

/// # Config
///
/// This struct is responsible for holding the configuration of the SMTPServer.
#[derive(Debug, Clone)]
pub struct Config<B>
where
    B: Default + Send + Sync + Clone,{
    /// # domain
    ///
    /// The domain of the SMTP server.
    pub domain: Option<String>,
    /// # use_tls
    ///
    /// Whether the SMTP server will use TLS or not.
    pub use_tls: bool,
    /// # workers
    ///
    /// The number of workers that will be used by the ThreadPool.
    pub workers: usize,
    /// # max_size
    ///
    /// The maximum size of the email that can be received.
    pub max_size: usize,
    /// # allowed_commands
    ///
    /// The allowed commands that the server will accept.
    pub allowed_commands: Vec<Commands>,
    /// # max_session_duration
    ///
    /// The maximum duration of a session.
    pub max_session_duration: Duration,
    /// # max_op_duration
    ///
    /// The maximum duration of an operation.
    pub max_op_duration: Duration,

    /// # controllers
    ///
    /// This field is responsible for holding the controllers that will be used by the server.
    pub controllers: Controllers<B>,

    /// # auth_mechanisms
    /// 
    /// This field is responsible for holding the authentication mechanisms that the SMTP server supports.
    pub auth_mechanisms: Vec<AuthMechanism>,
}

/// # Auth Mechanism
/// 
/// This enum represents the authentication mechanisms that the SMTP server supports.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthMechanism {
    /// # Plain
    ///
    /// The PLAIN authentication mechanism.
    Plain,
    /// # Login
    ///
    /// The LOGIN authentication mechanism.
    Login,
    /// # CRAM-MD5
    ///
    /// The CRAM-MD5 authentication mechanism.
    CramMD5,

    /// # OAuth2
    ///
    /// The OAuth2 authentication mechanism.
    OAuth2,

    /// # Unknown
    ///
    /// An unknown authentication mechanism.
    Unknown(String),
}

/// # Controllers
///
/// This struct is responsible for holding the controllers that will be used by the SMTPServer.
#[derive(Debug)]
pub struct Controllers<B> {
    /// # on_conn controller
    pub on_conn: Option<OnConnController<B>>,
    /// # on_auth controller
    pub on_auth: Option<OnAuthController<B>>,
    /// # on_email controller
    pub on_email: Option<OnEmailController<B>>,
    /// # on_reset controller
    pub on_reset: Option<OnResetController<B>>,
    /// # on_close controller
    pub on_close: Option<OnCloseController<B>>,
    /// # on_mail_cmd controller
    pub on_mail_cmd: Option<OnMailCommandController<B>>,
    /// # on_rcpt_cmd controller
    pub on_rcpt_cmd: Option<OnRCPTCommandController<B>>,
    /// # on_unknown_cmd controller
    pub on_unknown_cmd: Option<OnUnknownCommandController<B>>,
}

/// # Clone for Controllers
///
/// This implementation is responsible for cloning the Controllers struct.
impl<B> Clone for Controllers<B>
where
    B: Default + Send + Sync + Clone,
{
    fn clone(&self) -> Self {
        Controllers {
            on_conn: self.on_conn.clone(),
            on_auth: self.on_auth.clone(),
            on_email: self.on_email.clone(),
            on_reset: self.on_reset.clone(),
            on_close: self.on_close.clone(),
            on_mail_cmd: self.on_mail_cmd.clone(),
            on_rcpt_cmd: self.on_rcpt_cmd.clone(),
            on_unknown_cmd: self.on_unknown_cmd.clone(),
        }
    }
}

impl<B> SMTPServer<B> 
where
    B: Default + Send + Sync + Clone,{
    /// # new
    ///
    /// Create a new SMTPServer with default values.
    pub fn new() -> Self {
        let dns_resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let dns_resolver = Arc::new(Mutex::new(dns_resolver));

        SMTPServer {
            listener: None,
            // threads_pool: None,
            tls_acceptor: None,
            dns_resolver,
            config: Config {
                domain: None,
                use_tls: false,
                workers: 1,
                max_size: 1024 * 1024 * 10, // 10 MB
                allowed_commands: vec![
                    Commands::HELO,
                    Commands::EHLO,
                    Commands::MAIL,
                    Commands::RCPT,
                    Commands::DATA,
                    Commands::RSET,
                    Commands::VRFY,
                    Commands::EXPN,
                    Commands::HELP,
                    Commands::NOOP,
                    Commands::QUIT,
                    Commands::AUTH,
                    Commands::STARTTLS,
                ],
                auth_mechanisms: vec![],
                max_session_duration: Duration::from_secs(15),
                max_op_duration: Duration::from_secs(5),
                controllers: Controllers {
                    on_conn: None,
                    on_auth: None,
                    on_email: None,
                    on_reset: None,
                    on_close: None,
                    on_mail_cmd: None,
                    on_rcpt_cmd: None,
                    on_unknown_cmd: None,
                },
            },
        }
    }

    /// # workers
    ///
    /// Set the number of workers to be used in the ThreadPool, 1 by default.
    pub fn workers(&mut self, workers: usize) -> &mut Self {
        log::info!("[🚧] Setting workers to {}", workers);
        self.config.workers = workers;
        self
    }

    /// # set_tls_acceptor
    ///
    /// Set the TLS Acceptor to be used when upgrading the connection to TLS.
    pub fn set_tls_acceptor(&mut self, acceptor: tokio_native_tls::TlsAcceptor) -> &mut Self {
        log::debug!("[📃] TLS Acceptor set");
        self.config.use_tls = true;
        self.tls_acceptor = Some(Arc::new(Mutex::new(acceptor)));
        self
    }

    /// # set_dns_resolver
    ///
    /// Set the DNS Resolver to be used when resolving the domain of the email.
    /// This ovverides the default DNS Resolver.
    pub fn set_dns_resolver(&mut self, resolver: TokioAsyncResolver) -> &mut Self {
        log::debug!("[📃] DNS Resolver set");
        self.dns_resolver = Arc::new(Mutex::new(resolver));
        self
    }

    /// # set_max_size
    ///
    /// Set the max size of the email that can be received.
    /// size in bytes
    pub fn set_max_size(&mut self, max_size: usize) -> &mut Self {
        log::debug!("[📃] Setting max size to {}", max_size);
        self.config.max_size = max_size;
        self
    }

    /// # set_allowed_commands
    ///
    /// Set the allowed commands that the server will accept.
    pub fn set_allowed_commands(&mut self, commands: Vec<Commands>) -> &mut Self {
        log::debug!("[📃] Setting allowed commands");
        self.config.allowed_commands = commands;
        self
    }

    /// # on_conn
    ///
    /// Set the OnConnController to be used when a connection is opened.
    pub fn on_conn(&mut self, on_conn: OnConnController<B>) -> &mut Self {
        log::debug!("[📃] Setting OnConnController");
        self.config.controllers.on_conn = Some(on_conn);
        self
    }

    /// # on_auth
    ///
    /// Set the OnAuthController to be used when an auth command is received.
    pub fn on_auth(&mut self, on_auth: OnAuthController<B>) -> &mut Self {
        log::debug!("[📃] Setting OnAuthController");
        self.config.controllers.on_auth = Some(on_auth);
        self
    }

    /// # on_email
    ///
    /// Set the OnEmailController to be used when a email is received.
    pub fn on_email(&mut self, on_email: OnEmailController<B>) -> &mut Self {
        log::debug!("[📃] Setting OnEmailController");
        self.config.controllers.on_email = Some(on_email);
        self
    }

    /// # on_reset
    ///
    /// Set the OnResetController to be used when a connection is reset.
    pub fn on_reset(&mut self, on_reset: OnResetController<B>) -> &mut Self {
        log::debug!("[📃] Setting OnResetController");
        self.config.controllers.on_reset = Some(on_reset);
        self
    }

    /// # on_close
    ///
    /// Set the OnCloseController to be used when a connection will be closed.
    pub fn on_close(&mut self, on_close: OnCloseController<B>) -> &mut Self {
        log::debug!("[📃] Setting OnCloseController");
        self.config.controllers.on_close = Some(on_close);
        self
    }

    /// # on_mail_cmd
    ///
    /// Set the OnMailCommandController to be used when a mail command is received usually indicating the MAIL FROM.
    pub fn on_mail_cmd(&mut self, on_mail_cmd: OnMailCommandController<B>) -> &mut Self {
        log::debug!("[📃] Setting OnMailCommandController");
        self.config.controllers.on_mail_cmd = Some(on_mail_cmd);
        self
    }

    /// # on_rcpt_cmd
    ///
    /// Set the OnRCPTCommandController to be used when a rcpt command is received.
    pub fn on_rcpt_cmd(&mut self, on_rcpt_cmd: OnRCPTCommandController<B>) -> &mut Self {
        log::debug!("[📃] Setting OnRCPTCommandController");
        self.config.controllers.on_rcpt_cmd = Some(on_rcpt_cmd);
        self
    }

    /// # on_unknown_cmd
    ///
    /// Set the OnUnknownCommandController to be used when an unknown command is received.
    pub fn on_unknown_cmd(&mut self, on_unknown_cmd: OnUnknownCommandController<B>) -> &mut Self {
        log::debug!("[📃] Setting OnUnknownCommandController");
        self.config.controllers.on_unknown_cmd = Some(on_unknown_cmd);
        self
    }

    /// # set_max_session_duration
    ///
    /// Set the max session duration.
    pub fn set_max_session_duration(&mut self, duration: Duration) -> &mut Self {
        log::debug!("[📃] Setting max session duration to {:?}", duration);
        self.config.max_session_duration = duration;
        self
    }

    /// # set_max_op_duration
    ///
    /// Set the max operation duration.
    pub fn set_max_op_duration(&mut self, duration: Duration) -> &mut Self {
        log::debug!("[📃] Setting max operation duration to {:?}", duration);
        self.config.max_op_duration = duration;
        self
    }

    /// # bind
    ///
    /// This function is responsible for binding the SMTPServer to a specific address.
    pub async fn bind(&mut self, address: SocketAddr) -> Result<&mut Self, tokio::io::Error> {
        log::info!("[🔗 ] Binding to {}", address);
        let listener = tokio::net::TcpListener::bind(address).await?;
        self.listener = Some(Arc::new(listener));
        Ok(self)
    }

    /// # set_auth_mechanisms
    /// 
    /// Set the authentication mechanisms that the SMTP server supports.
    pub fn set_auth_mechanisms(&mut self, mechanisms: Vec<AuthMechanism>) -> &mut Self {
        log::debug!("[📃] Setting authentication mechanisms");
        self.config.auth_mechanisms = mechanisms;
        self
    }

    /// # run
    ///
    /// This function is responsible for running the SMTPServer, accepting connections and handling them, binding is required before running.
    pub async fn run(&mut self)
    where
        B: 'static + Default + Send + Sync + Clone,
    {
        // Clone the listener to be used in the main loop
        let listener = match self.listener.clone() {
            Some(lstnr) => lstnr,
            None => panic!("There isn't listener"),
        };

        // Start the main loop for accepting connections
        log::info!("[🔧] Starting main loop for accepting connections");
        loop {
            // Accept a new connection
            let (socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(err) => {
                    log::error!(
                        "An error ocurred while trying to accept and TcpStream connection {}",
                        err
                    );
                    continue;
                }
            };

            let peer_addr = match socket.peer_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    log::error!("Failed to get peer address: {}", err);
                    continue;
                }
            };

            log::trace!(
                "[🔍] Connection received from {}",
                peer_addr.ip()
            );

            // Clone the thread pool, use_tls, tls_acceptor and controllers to be used in the tokio::spawn
            // let tls_acceptor = self.tls_acceptor.clone();
            let controllers = self.config.controllers.clone();
            let dns_resolver = self.dns_resolver.clone();
            let config = self.config.clone();

            // Spawn a new task to handle the connection
            tokio::spawn(async move {
                log::trace!("[🟢] Initializing TCP connection");

                // Create a new SMTPConnection and wrap it in an Arc<Mutex> to be shared safely between threads
                let conn = Arc::new(Mutex::new(SMTPConnection {
                    peer_addr,
                    use_tls: false,
                    tls_buff_socket: None,
                    tcp_buff_socket: Some(Arc::new(Mutex::new( socket))),
                    buffer: Vec::new(),
                    mail_buffer: Vec::new(),
                    status: SMTPConnectionStatus::WaitingCommand,
                    dns_resolver,
                    state: Arc::new(Mutex::new(B::default())),
                    tracing_commands: Vec::new(),
                }));

                handle_connection_with_timeout(
                                // tls_acceptor,
                                conn,
                                controllers,
                                &config,
                            ).await;
            });
        }
    }
}
