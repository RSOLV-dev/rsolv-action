const code = `
function handleRequest(userInput) {
  const query = "SELECT * FROM users WHERE id = " + userInput;
  db.query(query);
}
`;

console.log(code);