/** @type {import('tailwindcss').Config} */
const plugin = require("tailwindcss/plugin")
const fs = require("fs")
const path = require("path")

module.exports = {
  darkMode: 'class',
  content: [
    "./lib/**/*.{ex,heex,eex}",
    "./lib/**/views/**/*.{ex,heex,eex}",
    "./lib/**/live/**/*.{ex,heex,eex}",
    "./lib/**/components/**/*.{ex,heex,eex}",
    "./assets/js/**/*.js"
  ],
  safelist: [
    'text-brand-blue',
    'bg-brand-blue',
    'text-brand-green',
    'bg-brand-green',
    'text-brand-dark',
    'bg-brand-dark',
    'text-brand-light',
    'bg-brand-light',
    'text-brand-white',
    'bg-brand-white',
    'hover:bg-brand-blue',
    'hover:bg-brand-green',
    'hover:text-brand-blue',
    'hover:text-brand-green',
    'btn-primary',
    'btn-success',
    'btn-outline',
    // GitHub-style color utilities
    'bg-canvas',
    'bg-subtle',
    'bg-inset',
    'text-muted',
    'text-subtle',
    'text-emphasis',
    'border-muted',
    'border-subtle',
    'text-accent',
    'text-success',
    'text-danger',
    'text-warning',
    'card',
    'card-subtle',
    'nav-bg',
    // Typography classes
    'prose-invert',
    'dark:prose-invert',
    // Dark mode support
    'dark:text-gray-100',
    'dark:text-gray-200',
    'dark:text-gray-300',
    'dark:text-gray-400',
    'dark:prose-headings:text-gray-200',
    'dark:prose-p:text-gray-300',
    'dark:prose-li:text-gray-300',
    'dark:prose-strong:text-gray-100',
    'dark:prose-a:text-blue-400',
    'dark:prose-blockquote:text-gray-300',
    'dark:prose-code:text-gray-200',
    'dark:group-hover:text-blue-400',
    'dark:hover:text-gray-200',
  ],
  theme: {
    extend: {
      typography: ({ theme }) => ({
        DEFAULT: {
          css: {
            '--tw-prose-body': theme('colors.gray.700'),
            '--tw-prose-headings': theme('colors.gray.900'),
            '--tw-prose-lead': theme('colors.gray.600'),
            '--tw-prose-links': theme('colors.blue.600'),
            '--tw-prose-bold': theme('colors.gray.900'),
            '--tw-prose-counters': theme('colors.gray.500'),
            '--tw-prose-bullets': theme('colors.gray.300'),
            '--tw-prose-hr': theme('colors.gray.200'),
            '--tw-prose-quotes': theme('colors.gray.900'),
            '--tw-prose-quote-borders': theme('colors.gray.200'),
            '--tw-prose-captions': theme('colors.gray.500'),
            '--tw-prose-code': theme('colors.gray.900'),
            '--tw-prose-pre-code': theme('colors.gray.200'),
            '--tw-prose-pre-bg': theme('colors.gray.800'),
            '--tw-prose-th-borders': theme('colors.gray.300'),
            '--tw-prose-td-borders': theme('colors.gray.200'),
            '--tw-prose-invert-body': theme('colors.gray.300'),
            '--tw-prose-invert-headings': theme('colors.gray.200'),
            '--tw-prose-invert-lead': theme('colors.gray.400'),
            '--tw-prose-invert-links': theme('colors.blue.400'),
            '--tw-prose-invert-bold': theme('colors.gray.200'),
            '--tw-prose-invert-counters': theme('colors.gray.400'),
            '--tw-prose-invert-bullets': theme('colors.gray.600'),
            '--tw-prose-invert-hr': theme('colors.gray.700'),
            '--tw-prose-invert-quotes': theme('colors.gray.100'),
            '--tw-prose-invert-quote-borders': theme('colors.gray.700'),
            '--tw-prose-invert-captions': theme('colors.gray.400'),
            '--tw-prose-invert-code': theme('colors.gray.200'),
            '--tw-prose-invert-pre-code': theme('colors.gray.300'),
            '--tw-prose-invert-pre-bg': 'rgb(0 0 0 / 50%)',
            '--tw-prose-invert-th-borders': theme('colors.gray.600'),
            '--tw-prose-invert-td-borders': theme('colors.gray.700'),
            maxWidth: 'none',
          },
        },
      }),
      colors: {
        brand: {
          blue: "#3366FF",     // Primary blue
          green: "#00CC66",    // Primary green
          dark: "#333333",     // Dark gray
          light: "#F5F5F5",    // Light gray
          white: "#FFFFFF",    // White
        },
        // GitHub-style color system using CSS variables
        canvas: 'var(--color-bg-canvas)',
        default: 'var(--color-bg-default)',
        subtle: 'var(--color-bg-subtle)',
        inset: 'var(--color-bg-inset)',
        
        fg: {
          DEFAULT: 'var(--color-fg-default)',
          muted: 'var(--color-fg-muted)',
          subtle: 'var(--color-fg-subtle)',
          emphasis: 'var(--color-fg-on-emphasis)',
        },
        
        border: {
          DEFAULT: 'var(--color-border-default)',
          muted: 'var(--color-border-muted)',
          subtle: 'var(--color-border-subtle)',
        },
        
        accent: {
          DEFAULT: 'var(--color-accent-fg)',
          emphasis: 'var(--color-accent-emphasis)',
        },
        
        success: 'var(--color-success-fg)',
        danger: 'var(--color-danger-fg)',
        warning: 'var(--color-warning-fg)',
      },
      backgroundColor: {
        canvas: 'var(--color-bg-canvas)',
        DEFAULT: 'var(--color-bg-default)',
        subtle: 'var(--color-bg-subtle)',
        inset: 'var(--color-bg-inset)',
      },
      textColor: {
        DEFAULT: 'var(--color-fg-default)',
        muted: 'var(--color-fg-muted)',
        subtle: 'var(--color-fg-subtle)',
        emphasis: 'var(--color-fg-on-emphasis)',
      },
      borderColor: {
        DEFAULT: 'var(--color-border-default)',
        muted: 'var(--color-border-muted)',
        subtle: 'var(--color-border-subtle)',
      },
      boxShadow: {
        sm: 'var(--color-shadow-small)',
        DEFAULT: 'var(--color-shadow-medium)',
        lg: 'var(--color-shadow-large)',
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
      let iconsDir = path.join(__dirname, "./deps/heroicons/optimized")
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