defmodule RsolvWeb.Components.Docs.CodeBlock do
  use Phoenix.Component

  @doc """
  Renders a code block with optional syntax highlighting and copy-to-clipboard functionality.

  ## Examples

      <.code_block language="elixir">
        defmodule MyApp do
          def hello, do: "world"
        end
      </.code_block>

      <.code_block language="yaml" filename=".github/workflows/rsolv.yml">
        name: RSOLV Security
        on: [push]
      </.code_block>

      <.code_block language="bash" show_line_numbers>
        mix deps.get
        mix compile
      </.code_block>

  ## Attributes

  - `language` - Programming language for syntax highlighting (default: "text")
  - `filename` - Optional filename to display in the header
  - `show_line_numbers` - Show line numbers (default: false)
  - `class` - Additional CSS classes
  """
  attr :language, :string, default: "text"
  attr :filename, :string, default: nil
  attr :show_line_numbers, :boolean, default: false
  attr :class, :string, default: ""
  slot :inner_block, required: true

  def code_block(assigns) do
    # Generate unique ID for copy functionality
    assigns = assign(assigns, :block_id, "code-#{System.unique_integer([:positive])}")

    ~H"""
    <div class={[
      "relative group rounded-lg overflow-hidden border border-slate-200 dark:border-slate-700",
      @class
    ]}>
      <!-- Header (if filename provided) -->
      <%= if @filename do %>
        <div class="flex items-center justify-between px-4 py-2 bg-slate-100 dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">
          <span class="text-xs font-mono text-slate-700 dark:text-slate-300">
            {@filename}
          </span>
          <span class="text-xs text-slate-500 dark:text-slate-500 uppercase">
            {@language}
          </span>
        </div>
      <% end %>
      
    <!-- Copy button -->
      <button
        type="button"
        class="absolute top-2 right-2 p-2 rounded-md bg-slate-700 dark:bg-slate-600 text-white opacity-0 group-hover:opacity-100 transition-opacity focus:opacity-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
        onclick={"copyCode('#{@block_id}')"}
        aria-label="Copy code"
        title="Copy to clipboard"
      >
        <svg
          class="h-4 w-4 copy-icon"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
          />
        </svg>
        <svg
          class="h-4 w-4 check-icon hidden"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M5 13l4 4L19 7"
          />
        </svg>
      </button>
      
    <!-- Code content -->
      <pre
        id={@block_id}
        class={[
          "overflow-x-auto p-4 text-sm",
          "bg-slate-900 dark:bg-slate-950",
          @show_line_numbers && "pl-12"
        ]}
      ><code class={[
        "language-#{@language}",
        "text-slate-100"
      ]}><%= render_slot(@inner_block) %></code></pre>
    </div>

    <script>
      // Copy code functionality
      window.copyCode = function(id) {
        const codeBlock = document.getElementById(id);
        const code = codeBlock.textContent;

        navigator.clipboard.writeText(code).then(() => {
          // Show check icon
          const btn = codeBlock.parentElement.querySelector('button');
          const copyIcon = btn.querySelector('.copy-icon');
          const checkIcon = btn.querySelector('.check-icon');

          copyIcon.classList.add('hidden');
          checkIcon.classList.remove('hidden');

          // Reset after 2 seconds
          setTimeout(() => {
            copyIcon.classList.remove('hidden');
            checkIcon.classList.add('hidden');
          }, 2000);
        });
      };
    </script>
    """
  end
end
