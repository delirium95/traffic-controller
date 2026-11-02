use std::thread;

fn main() {
    thread::spawn(f);
    thread::spawn(f);
    println!("Hello from the main thread");
}

fn f() {
    println!("Hello from another thread!");
    let id = thread::current().id();
    println!("thread id: {:?}", id);
}
