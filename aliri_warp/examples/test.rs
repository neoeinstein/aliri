use aliri_jose::Jwt;
use aliri_warp as aliri;
use warp::Filter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let hi = warp::path("hello")
        .and(warp::path::param())
        .and(warp::header("user-agent"))
        .and(aliri::jwt::optional())
        .map(|param: String, agent: String, auth: Option<Jwt>| {
            if let Some(auth) = auth {
                format!("Hello {}, whose agent is {}, auth: {}", param, agent, auth)
            } else {
                format!(
                    "Hello {}, whose agent is {}, and isn't authorized!",
                    param, agent
                )
            }
        });

    let (addr, fut) =
        warp::serve(hi).bind_ephemeral("127.0.0.1:0".parse::<std::net::SocketAddr>()?);

    println!("listening at: {}", addr);

    Ok(fut.await)
}
