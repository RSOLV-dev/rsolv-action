defmodule RsolvWeb.Components.DarkModeHelpers do
  @moduledoc """
  Helper functions for consistent dark mode styling across the application.
  These helpers generate Tailwind class strings for common patterns.
  """

  @doc """
  Returns classes for standard card/panel styling with dark mode support.
  
  ## Examples
      
      <div class={card_classes()}>
        Content here
      </div>
      
      <div class={card_classes("border-t-4 border-red-500")}>
        Card with additional classes
      </div>
  """
  def card_classes(additional_classes \\ "") do
    "bg-white dark:bg-dark-800 #{additional_classes}"
  end

  @doc """
  Returns classes for form inputs with dark mode support.
  """
  def input_classes(additional_classes \\ "") do
    "shadow appearance-none border dark:border-gray-600 rounded w-full py-2 px-3 " <>
    "text-gray-700 dark:text-gray-200 bg-white dark:bg-dark-700 " <>
    "leading-tight focus:outline-none focus:shadow-outline " <>
    "focus:ring-2 focus:ring-brand-blue dark:focus:ring-brand-green #{additional_classes}"
  end

  @doc """
  Returns classes for form labels with dark mode support.
  """
  def label_classes(additional_classes \\ "") do
    "block text-gray-700 dark:text-gray-300 text-sm font-bold mb-2 #{additional_classes}"
  end

  @doc """
  Returns classes for section backgrounds with dark mode support.
  
  ## Options
    * `:variant` - :default | :light | :dark
  """
  def section_classes(variant \\ :default, additional_classes \\ "") do
    base = case variant do
      :light -> "bg-brand-light dark:bg-dark-900"
      :dark -> "bg-gray-50 dark:bg-dark-900"
      _ -> "bg-white dark:bg-dark-950"
    end
    "#{base} #{additional_classes}"
  end

  @doc """
  Returns classes for text with proper dark mode contrast.
  
  ## Options
    * `:variant` - :default | :muted | :heading
  """
  def text_classes(variant \\ :default, additional_classes \\ "") do
    base = case variant do
      :muted -> "text-gray-600 dark:text-gray-400"
      :heading -> "text-gray-900 dark:text-white"
      _ -> "text-gray-700 dark:text-gray-300"
    end
    "#{base} #{additional_classes}"
  end

  @doc """
  Returns classes for buttons with dark mode support.
  Already defined in CSS but included here for completeness.
  """
  def button_classes(variant \\ :primary, additional_classes \\ "") do
    case variant do
      :primary -> "btn-primary #{additional_classes}"
      :secondary -> "btn-outline #{additional_classes}"
      :success -> "btn-success #{additional_classes}"
      _ -> additional_classes
    end
  end
end