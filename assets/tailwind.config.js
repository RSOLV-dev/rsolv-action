// See the Tailwind configuration guide for advanced usage
// https://tailwindcss.com/docs/configuration

const plugin = require("tailwindcss/plugin")
const fs = require("fs")
const path = require("path")

module.exports = {
  darkMode: 'class',
  content: [
    "./js/**/*.js",
    "../lib/rsolv_web.ex",
    "../lib/rsolv_web/**/*.{ex,heex,leex,sface}"
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          blue: "#3366FF",     // Primary blue
          green: "#00CC66",    // Primary green
          dark: "#333333",     // Dark gray
          light: "#F5F5F5",    // Light gray
          white: "#FFFFFF",    // White
        },
        // Dark mode color palette
        dark: {
          50: "#f8fafc",
          100: "#f1f5f9", 
          200: "#e2e8f0",
          300: "#cbd5e1",
          400: "#94a3b8",
          500: "#64748b",
          600: "#475569",
          700: "#334155",
          800: "#1e293b",
          900: "#0f172a",
          950: "#020617"
        }
      },
      fontFamily: {
        'sans': ['Space Grotesk', 'system-ui', 'sans-serif'],
        'mono': ['Iosevka', 'ui-monospace', 'SFMono-Regular', 'monospace']
      }
    },
  },
  plugins: [
    require("@tailwindcss/forms"),
    require("@tailwindcss/typography"),
    // Allows prefixing tailwind classes with LiveView classes to add rules
    // only when LiveView classes are applied, for example:
    //
    //     <div class="phx-click-loading:animate-ping">
    //
    plugin(({addVariant}) => addVariant("phx-no-feedback", [".phx-no-feedback&", ".phx-no-feedback &"])),
    plugin(({addVariant}) => addVariant("phx-click-loading", [".phx-click-loading&", ".phx-click-loading &"])),
    plugin(({addVariant}) => addVariant("phx-submit-loading", [".phx-submit-loading&", ".phx-submit-loading &"])),
    plugin(({addVariant}) => addVariant("phx-change-loading", [".phx-change-loading&", ".phx-change-loading &"])),

    // Embeds Heroicons (https://heroicons.com) into your app.css bundle
    // See your `CoreComponents.icon/1` for more information.
    //
    plugin(function({matchComponents, theme}) {
      let iconsDir = path.join(__dirname, "../deps/heroicons/optimized")
      let values = {}
      let icons = [
        ["", "/24/outline"],
        ["solid-", "/24/solid"],
        ["mini-", "/20/solid"],
        ["micro-", "/16/solid"]
      ]
      
      // For now, let's create a placeholder value since we're having path issues with heroicons
      let placeholderSvg = '<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M9.879 7.519c1.171-1.025 3.071-1.025 4.242 0 1.172 1.025 1.172 2.687 0 3.712-.203.179-.43.326-.67.442-.745.361-1.45.999-1.45 1.827v.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 5.25h.008v.008H12v-.008Z" /></svg>'

      // Try to use fs.readdirSync only if the directory exists
      try {
        icons.forEach(([prefix, dir]) => {
          try {
            fs.readdirSync(path.join(iconsDir, dir)).forEach(file => {
              let name = path.basename(file, ".svg")
              values[name === "question-mark-circle" ? "question" : name] = [prefix, file]
            })
          } catch (e) {
            console.warn(`Warning: Could not read icon directory: ${dir}`)
          }
        })
      } catch (e) {
        console.warn("Warning: Could not access heroicons directory")
      }
      
      matchComponents({
        "hero": ({name, style}) => {
          // Use a placeholder SVG for now since we're having path issues
          return {
            [`--hero-${name}`]: `url('data:image/svg+xml;utf8,${placeholderSvg}')`,
            "-webkit-mask": `var(--hero-${name})`,
            "mask": `var(--hero-${name})`,
            "mask-repeat": "no-repeat",
            "background-color": "currentColor",
            "vertical-align": "middle",
            "display": "inline-block",
            "width": style === "solid" || style === "outline" ? theme("spacing.6") : style === "mini" ? theme("spacing.5") : theme("spacing.4"),
            "height": style === "solid" || style === "outline" ? theme("spacing.6") : style === "mini" ? theme("spacing.5") : theme("spacing.4")
          }
        }
      }, {values})
    })
  ]
}