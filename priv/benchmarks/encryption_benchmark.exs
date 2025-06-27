#!/usr/bin/env elixir

# Encryption Performance Benchmark for RFC-031

# Load dependencies
Mix.start()
Mix.env(:dev)
Code.require_file("lib/rsolv_api/ast/encryption.ex")
Code.require_file("lib/rsolv_api/ast/session_manager.ex")
Code.require_file("lib/rsolv_api/ast/file_transmission.ex")

defmodule EncryptionBenchmark do
  def run do
    IO.puts("RFC-031 Encryption Performance Benchmark")
    IO.puts("=" |> String.duplicate(50))
    IO.puts("")
    
    # Generate test data
    key = RsolvApi.AST.Encryption.generate_key()
    session = %RsolvApi.AST.SessionManager.Session{
      id: "bench-session",
      customer_id: "bench-customer",
      encryption_key: key,
      created_at: DateTime.utc_now(),
      expires_at: DateTime.add(DateTime.utc_now(), 3600, :second)
    }
    
    # Test different file sizes
    sizes = [
      {1_024, "1KB"},
      {10_240, "10KB"},
      {102_400, "100KB"},
      {1_048_576, "1MB"},
      {5_242_880, "5MB"},
      {10_485_760, "10MB"}
    ]
    
    IO.puts("Encryption/Decryption Performance:")
    IO.puts("-" |> String.duplicate(50))
    IO.puts("Size\t\tEncrypt (ms)\tDecrypt (ms)\tThroughput")
    IO.puts("-" |> String.duplicate(50))
    
    for {size, label} <- sizes do
      data = :crypto.strong_rand_bytes(size)
      
      # Benchmark encryption
      {encrypt_time, {ciphertext, iv, auth_tag}} = :timer.tc(fn ->
        RsolvApi.AST.Encryption.encrypt(data, key)
      end)
      
      # Benchmark decryption
      {decrypt_time, {:ok, _plaintext}} = :timer.tc(fn ->
        RsolvApi.AST.Encryption.decrypt(ciphertext, key, iv, auth_tag)
      end)
      
      # Calculate throughput (MB/s)
      encrypt_throughput = (size / 1024 / 1024) / (encrypt_time / 1_000_000)
      decrypt_throughput = (size / 1024 / 1024) / (decrypt_time / 1_000_000)
      
      IO.puts("#{label}\t\t#{format_time(encrypt_time)}\t\t#{format_time(decrypt_time)}\t\t#{format_throughput(encrypt_throughput, decrypt_throughput)}")
    end
    
    IO.puts("")
    
    # Benchmark file transmission
    IO.puts("File Transmission Performance (with chunking):")
    IO.puts("-" |> String.duplicate(50))
    IO.puts("Size\t\tPrepare (ms)\tReceive (ms)")
    IO.puts("-" |> String.duplicate(50))
    
    for {size, label} <- sizes do
      data = :crypto.strong_rand_bytes(size)
      
      # Benchmark preparation
      {prepare_time, {:ok, prepared}} = :timer.tc(fn ->
        RsolvApi.AST.FileTransmission.prepare_for_transmission(data, session)
      end)
      
      # Benchmark receiving
      {receive_time, {:ok, _received}} = :timer.tc(fn ->
        RsolvApi.AST.FileTransmission.receive_transmission(
          prepared.chunks,
          prepared.metadata.content_hash,
          session
        )
      end)
      
      IO.puts("#{label}\t\t#{format_time(prepare_time)}\t\t#{format_time(receive_time)}")
    end
    
    IO.puts("")
    
    # Concurrent operations benchmark
    IO.puts("Concurrent Operations (100 x 10KB files):")
    IO.puts("-" |> String.duplicate(50))
    
    data = :crypto.strong_rand_bytes(10_240)
    
    # Sequential
    {seq_time, _} = :timer.tc(fn ->
      for _ <- 1..100 do
        {ciphertext, iv, auth_tag} = RsolvApi.AST.Encryption.encrypt(data, key)
        {:ok, _} = RsolvApi.AST.Encryption.decrypt(ciphertext, key, iv, auth_tag)
      end
    end)
    
    # Concurrent
    {conc_time, _} = :timer.tc(fn ->
      tasks = for _ <- 1..100 do
        Task.async(fn ->
          {ciphertext, iv, auth_tag} = RsolvApi.AST.Encryption.encrypt(data, key)
          {:ok, _} = RsolvApi.AST.Encryption.decrypt(ciphertext, key, iv, auth_tag)
        end)
      end
      
      Task.await_many(tasks, 30_000)
    end)
    
    IO.puts("Sequential: #{format_time(seq_time)} total, #{format_time(div(seq_time, 100))} per operation")
    IO.puts("Concurrent: #{format_time(conc_time)} total, #{format_time(div(conc_time, 100))} per operation")
    IO.puts("Speedup: #{Float.round(seq_time / conc_time, 2)}x")
    
    IO.puts("")
    
    # Memory usage
    IO.puts("Memory Usage Test (100MB file):")
    IO.puts("-" |> String.duplicate(50))
    
    initial_memory = :erlang.memory(:total)
    
    large_data = :crypto.strong_rand_bytes(100 * 1024 * 1024)
    {:ok, prepared} = RsolvApi.AST.FileTransmission.prepare_for_transmission(large_data, session)
    
    peak_memory = :erlang.memory(:total)
    
    # Force garbage collection
    :erlang.garbage_collect()
    
    final_memory = :erlang.memory(:total)
    
    IO.puts("Initial memory: #{format_memory(initial_memory)}")
    IO.puts("Peak memory: #{format_memory(peak_memory)}")
    IO.puts("Final memory: #{format_memory(final_memory)}")
    IO.puts("Memory used: #{format_memory(peak_memory - initial_memory)}")
    IO.puts("Chunks created: #{length(prepared.chunks)}")
    
    IO.puts("")
    IO.puts("Benchmark complete!")
  end
  
  defp format_time(microseconds) when microseconds < 1000 do
    "#{microseconds}μs"
  end
  
  defp format_time(microseconds) when microseconds < 1_000_000 do
    "#{Float.round(microseconds / 1000, 2)}ms"
  end
  
  defp format_time(microseconds) do
    "#{Float.round(microseconds / 1_000_000, 2)}s"
  end
  
  defp format_throughput(encrypt_mb_per_sec, decrypt_mb_per_sec) do
    "#{Float.round(encrypt_mb_per_sec, 1)}/#{Float.round(decrypt_mb_per_sec, 1)} MB/s"
  end
  
  defp format_memory(bytes) when bytes < 1024 do
    "#{bytes} B"
  end
  
  defp format_memory(bytes) when bytes < 1024 * 1024 do
    "#{Float.round(bytes / 1024, 2)} KB"
  end
  
  defp format_memory(bytes) do
    "#{Float.round(bytes / 1024 / 1024, 2)} MB"
  end
end

# Load the application
Application.load(:rsolv_api)

# Run the benchmark
EncryptionBenchmark.run()