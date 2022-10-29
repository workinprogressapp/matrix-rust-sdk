use std::io::Write;

use anyhow::Result;
use clap::Parser;
use matrix_sdk::{
    config::SyncSettings,
    ruma::{
        api::client::room::create_room::v3::Request as CreateRoomRequest,
        events::room::message::RoomMessageEventContent,
    },
    Client,
};
use url::Url;

#[derive(Parser, Debug)]
struct Cli {
    /// The homeserver to connect to.
    homeserver: Url,

    /// The user name that should be used for the login.
    user_name: String,

    /// The password that should be used for the login.
    password: String,

    /// Set the proxy that should be used for the connection.
    #[clap(short, long)]
    proxy: Option<Url>,

    /// Enable verbose logging output.
    #[clap(short, long, action)]
    verbose: bool,
}

async fn login(cli: Cli) -> Result<Client> {
    let mut builder =
        Client::builder().homeserver_url(cli.homeserver).sled_store("./", Some("some password"));

    if let Some(proxy) = cli.proxy {
        builder = builder.proxy(proxy);
    }

    let client = builder.build().await?;

    client
        .login_username(&cli.user_name, &cli.password)
        .initial_device_display_name("rust-sdk")
        .send()
        .await?;

    Ok(client)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt::init();
    }

    let client = login(cli).await?;
    let sync_settings = SyncSettings::default();

    client.sync_once(sync_settings.clone()).await?;

    tokio::spawn({
        let client = client.clone();
        async move { client.sync(sync_settings).await }
    });

    loop {
        print!("Creating a new room, input a room name?: ");
        std::io::stdout().flush().expect("We should be able to flush stdout");

        let mut room_name = String::new();
        std::io::stdin().read_line(&mut room_name).expect("error: unable to read user input");

        let mut request = CreateRoomRequest::new();
        request.name = Some(&room_name);

        let room = client.create_room(request).await?;

        println!("Successfully created a room, room_id {:?}", room.room_id());

        let content = RoomMessageEventContent::text_plain("Hello new room");
        room.send(content, None).await?;
    }
}
