use realworld::logcore;

fn main() {
    dotenv::dotenv().ok();
    logcore::probe_error();
}
