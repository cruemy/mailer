use std::io::{stdin, stdout, Write};

fn main() {
  let date = String::new();
  let weather = String::new();
  let word = read_line();


  println!("El login es: {}", word);
  // println!("Hello, world!");
}

pub fn read_line()-> String{
  let mut input = String::new();
  stdin().read_line(&mut input).expect("Didn't enter a correct string");

  //remove carret and new line character
  if let Some('\n')=input.chars().next_back() {
    input.pop();
  }
  if let Some('\r')=input.chars().next_back() {
    input.pop();
  }

  return input
}
