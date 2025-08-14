#!/usr/bin/env bun
// Build script for Phoenix assets using Bun and Tailwind CSS
import { $ } from "bun";
import { watch } from "fs";
import { join } from "path";

const args = process.argv.slice(2);
const isWatch = args.includes("--watch");
const isDeploy = args.includes("--deploy");

// Paths
const cssInput = join(__dirname, "css/app.css");
const cssOutput = join(__dirname, "../priv/static/assets/app.css");
const jsInput = join(__dirname, "js/app.js");
const jsOutput = join(__dirname, "../priv/static/assets/app.js");

// Tailwind build function
async function buildCSS() {
  console.log("Building CSS with Tailwind...");
  
  const tailwindArgs = [
    "--input=" + cssInput,
    "--output=" + cssOutput,
    "--config=" + join(__dirname, "tailwind.config.js")
  ];
  
  if (isDeploy) {
    tailwindArgs.push("--minify");
  }
  
  try {
    await $`npx tailwindcss ${tailwindArgs}`;
    console.log("✓ CSS built successfully");
  } catch (error) {
    console.error("✗ CSS build failed:", error);
    process.exit(1);
  }
}

// JavaScript build function using Bun
async function buildJS() {
  console.log("Building JavaScript with Bun...");
  
  try {
    const result = await Bun.build({
      entrypoints: [jsInput],
      outdir: join(__dirname, "../priv/static/assets"),
      target: "browser",
      format: "esm",
      splitting: true,
      minify: isDeploy,
      sourcemap: !isDeploy ? "external" : "none",
      naming: "[dir]/[name].[ext]",
      external: ["/fonts/*", "/images/*"],
    });
    
    if (!result.success) {
      console.error("✗ JS build failed:", result.logs);
      process.exit(1);
    }
    
    console.log("✓ JavaScript built successfully");
  } catch (error) {
    console.error("✗ JS build failed:", error);
    process.exit(1);
  }
}

// Main build function
async function build() {
  console.log(isDeploy ? "Building for production..." : "Building for development...");
  
  // Build in parallel
  await Promise.all([buildCSS(), buildJS()]);
  
  console.log("✓ All assets built successfully");
}

// Watch mode
async function watchAssets() {
  console.log("Watching for changes...");
  
  // Initial build
  await build();
  
  // Watch CSS files
  watch(join(__dirname, "css"), { recursive: true }, async (event, filename) => {
    if (filename?.endsWith(".css")) {
      console.log(`CSS changed: ${filename}`);
      await buildCSS();
    }
  });
  
  // Watch JS files
  watch(join(__dirname, "js"), { recursive: true }, async (event, filename) => {
    if (filename?.endsWith(".js") || filename?.endsWith(".ts")) {
      console.log(`JS changed: ${filename}`);
      await buildJS();
    }
  });
  
  // Watch Tailwind config
  watch(join(__dirname, "tailwind.config.js"), async () => {
    console.log("Tailwind config changed");
    await buildCSS();
  });
  
  console.log("✓ Watching assets...");
}

// Run the appropriate mode
if (isWatch) {
  watchAssets().catch(console.error);
} else {
  build().catch((error) => {
    console.error(error);
    process.exit(1);
  });
}