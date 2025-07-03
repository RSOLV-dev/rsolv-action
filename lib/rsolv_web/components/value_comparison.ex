defmodule RsolvWeb.Components.ValueComparison do
  use Phoenix.Component

  def simple_comparison(assigns) do
    ~H"""
    <div class="bg-gradient-to-r from-brand-red to-brand-orange p-8 rounded-xl shadow-xl">
      <h3 class="text-2xl font-bold text-white mb-6 text-center">The RSOLV Advantage</h3>
      
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Manual Fix -->
        <div class="bg-white p-6 rounded-lg">
          <h4 class="text-lg font-semibold text-brand-red mb-4">Traditional Manual Fix</h4>
          <ul class="space-y-3">
            <li class="flex items-center">
              <span class="hero-solid-clock w-5 h-5 text-brand-red mr-3"></span>
              <span>2-3 hours developer time</span>
            </li>
            <li class="flex items-center">
              <span class="hero-solid-currency-dollar w-5 h-5 text-brand-red mr-3"></span>
              <span class="font-bold">$300-450 cost</span>
            </li>
            <li class="flex items-center">
              <span class="hero-solid-x-circle w-5 h-5 text-brand-red mr-3"></span>
              <span>Context switching overhead</span>
            </li>
            <li class="flex items-center">
              <span class="hero-solid-calendar w-5 h-5 text-brand-red mr-3"></span>
              <span>Days/weeks in backlog</span>
            </li>
          </ul>
        </div>
        
        <!-- RSOLV Fix -->
        <div class="bg-white p-6 rounded-lg border-2 border-brand-green">
          <h4 class="text-lg font-semibold text-brand-green mb-4">RSOLV Automated Fix</h4>
          <ul class="space-y-3">
            <li class="flex items-center">
              <span class="hero-solid-lightning-bolt w-5 h-5 text-brand-green mr-3"></span>
              <span>Minutes to generate fix</span>
            </li>
            <li class="flex items-center">
              <span class="hero-solid-currency-dollar w-5 h-5 text-brand-green mr-3"></span>
              <span class="font-bold">$15 per fix</span>
            </li>
            <li class="flex items-center">
              <span class="hero-solid-check-circle w-5 h-5 text-brand-green mr-3"></span>
              <span>No context switching</span>
            </li>
            <li class="flex items-center">
              <span class="hero-solid-rocket-launch w-5 h-5 text-brand-green mr-3"></span>
              <span>Immediate resolution</span>
            </li>
          </ul>
        </div>
      </div>
      
      <div class="mt-8 text-center">
        <p class="text-white text-xl font-bold">
          Save <span class="text-yellow-300">95%</span> on every fix
        </p>
        <p class="text-white/90 text-lg mt-2">
          That's a <span class="font-bold">2,000% ROI</span> on your investment
        </p>
      </div>
    </div>
    """
  end

  def quick_roi_message(assigns) do
    ~H"""
    <div class="bg-brand-light p-6 rounded-lg text-center">
      <h4 class="text-xl font-bold text-brand-blue mb-3">Simple Math, Massive Returns</h4>
      <div class="flex flex-col md:flex-row items-center justify-center gap-4">
        <div class="flex items-center">
          <span class="text-lg">Manual Fix:</span>
          <span class="text-2xl font-bold text-brand-red ml-2">$300+</span>
        </div>
        <span class="text-2xl">→</span>
        <div class="flex items-center">
          <span class="text-lg">RSOLV Fix:</span>
          <span class="text-2xl font-bold text-brand-green ml-2">$15</span>
        </div>
        <span class="text-2xl">=</span>
        <div class="flex items-center">
          <span class="text-2xl font-bold text-brand-blue">2,000% ROI</span>
        </div>
      </div>
      <p class="mt-4 text-gray-600">
        Start with 10 free fixes to prove the value
      </p>
    </div>
    """
  end
end