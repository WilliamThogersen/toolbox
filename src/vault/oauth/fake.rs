use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

pub struct TokenServer {
    pub url: String,
    pub bodies: mpsc::Receiver<String>,
}

pub fn token_server(replies: Vec<(u16, String)>) -> TokenServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}/token", listener.local_addr().unwrap().port());
    let (tx, bodies) = mpsc::channel();
    thread::spawn(move || {
        for (status, reply) in replies {
            let (mut stream, _) = listener.accept().unwrap();
            tx.send(read_body(&stream)).unwrap();
            write!(
                stream,
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                reply.len()
            )
            .unwrap();
        }
    });
    TokenServer { url, bodies }
}

fn read_body(stream: &TcpStream) -> String {
    let mut reader = BufReader::new(stream);
    let mut length = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    String::from_utf8(body).unwrap()
}

pub fn visit(url: &str) {
    let parsed = url::Url::parse(url).unwrap();
    let mut stream = TcpStream::connect((parsed.host_str().unwrap(), parsed.port().unwrap())).unwrap();
    let target = match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_string(),
    };
    write!(stream, "GET {target} HTTP/1.1\r\nhost: 127.0.0.1\r\naccept: text/html\r\n\r\n").unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
}

pub fn tokens(access: &str, refresh: Option<&str>, expires_in: Option<u64>) -> String {
    let mut reply = serde_json::json!({ "access_token": access, "token_type": "Bearer" });
    if let Some(refresh) = refresh {
        reply["refresh_token"] = refresh.into();
    }
    if let Some(lifetime) = expires_in {
        reply["expires_in"] = lifetime.into();
    }
    reply.to_string()
}
