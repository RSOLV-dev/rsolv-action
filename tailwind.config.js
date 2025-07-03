/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./lib/**/*.{ex,heex,eex}",
    "./lib/**/views/**/*.{ex,heex,eex}",
    "./lib/**/live/**/*.{ex,heex,eex}",
    "./lib/**/components/**/*.{ex,heex,eex}",
    "./assets/js/**/*.js"
  ],
  theme: {
    extend: {},
  },
  plugins: [],
}