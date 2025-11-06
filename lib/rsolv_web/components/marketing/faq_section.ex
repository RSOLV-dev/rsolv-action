defmodule RsolvWeb.Components.Marketing.FaqSection do
  @moduledoc """
  Reusable FAQ section component for marketing pages.

  Displays a list of frequently asked questions with consistent styling.
  Supports dark mode and includes optional CTA at the bottom.

  ## Examples

      <FaqSection.faq_section
        title="Frequently Asked Questions"
        faqs={Rsolv.PricingData.faqs()}
        cta_text="Contact Us"
        cta_link="/contact"
      />
  """
  use Phoenix.Component

  alias RsolvWeb.Components.Marketing.Icons

  @doc """
  Renders an FAQ section with questions and optional CTA.

  ## Attributes

    - title: Section heading (default: "Frequently Asked Questions")
    - faqs: List of %{question: string, answer: string} maps
    - cta_text: Optional CTA button text
    - cta_link: Optional CTA button link
    - cta_prompt: Optional text above CTA button
  """
  attr :title, :string, default: "Frequently Asked Questions"
  attr :faqs, :list, required: true, doc: "List of %{question: string, answer: string}"
  attr :cta_text, :string, default: nil
  attr :cta_link, :string, default: nil
  attr :cta_prompt, :string, default: "Still have questions?"
  attr :class, :string, default: ""

  def faq_section(assigns) do
    ~H"""
    <div class={"bg-gray-50 dark:bg-gray-800 px-6 py-24 sm:py-32 lg:px-8 #{@class}"}>
      <div class="mx-auto max-w-4xl">
        <h2 class="text-4xl font-semibold tracking-tight text-gray-900 dark:text-white text-center mb-16">
          {@title}
        </h2>

        <dl class="space-y-8">
          <%= for faq <- @faqs do %>
            <.faq_item question={faq.question} answer={faq.answer} />
          <% end %>
        </dl>

        <%= if @cta_text && @cta_link do %>
          <div class="mt-16 text-center">
            <p class="text-lg text-gray-600 dark:text-gray-400 mb-6">
              {@cta_prompt}
            </p>
            <a
              href={@cta_link}
              class="inline-flex items-center justify-center rounded-md bg-blue-600 px-6 py-3 text-base font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 dark:bg-blue-500 dark:hover:bg-blue-400"
            >
              {@cta_text}
            </a>
          </div>
        <% end %>
      </div>
    </div>
    """
  end

  # Private components

  attr :question, :string, required: true
  attr :answer, :string, required: true

  defp faq_item(assigns) do
    ~H"""
    <div class="flex gap-4">
      <div class="flex-shrink-0 text-blue-600 dark:text-blue-400 mt-1">
        {Phoenix.HTML.raw(Icons.checkmark_circle())}
      </div>
      <div class="flex-1">
        <dt class="text-lg font-semibold text-gray-900 dark:text-white mb-2">
          {@question}
        </dt>
        <dd class="text-base text-gray-600 dark:text-gray-400">
          {@answer}
        </dd>
      </div>
    </div>
    """
  end
end
