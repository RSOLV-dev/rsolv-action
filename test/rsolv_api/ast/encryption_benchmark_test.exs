defmodule RsolvApi.AST.EncryptionBenchmarkTest do
  use ExUnit.Case, async: false
  
  alias RsolvApi.AST.Encryption
  alias RsolvApi.AST.FileTransmission
  alias RsolvApi.AST.SessionManager
  
  @tag :benchmark
  test "encryption performance benchmark" do
    IO.puts("\n\nRFC-031 Encryption Performance Benchmark")
    IO.puts("=" |> String.duplicate(50))
    
    # Generate test data
    key = Encryption.generate_key()
    session = %SessionManager.Session{
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
      {5_242_880, "5MB"}
    ]
    
    IO.puts("\nEncryption/Decryption Performance:")
    IO.puts("Size\t\tEncrypt\t\tDecrypt\t\tThroughput")
    IO.puts("-" |> String.duplicate(50))
    
    for {size, label} <- sizes do
      data = :crypto.strong_rand_bytes(size)
      
      # Benchmark encryption
      {encrypt_time, {ciphertext, iv, auth_tag}} = :timer.tc(fn ->
        Encryption.encrypt(data, key)
      end)
      
      # Benchmark decryption
      {decrypt_time, {:ok, _plaintext}} = :timer.tc(fn ->
        Encryption.decrypt(ciphertext, key, iv, auth_tag)
      end)
      
      # Calculate throughput (MB/s)
      encrypt_throughput = (size / 1024 / 1024) / (encrypt_time / 1_000_000)
      
      encrypt_ms = Float.round(encrypt_time / 1000, 2)
      decrypt_ms = Float.round(decrypt_time / 1000, 2)
      throughput_mb = Float.round(encrypt_throughput, 1)
      
      IO.puts("#{label}\t\t#{encrypt_ms}ms\t\t#{decrypt_ms}ms\t\t#{throughput_mb} MB/s")
    end
    
    # File transmission benchmark
    IO.puts("\nFile Transmission Performance:")
    IO.puts("Size\t\tPrepare\t\tReceive")
    IO.puts("-" |> String.duplicate(50))
    
    for {size, label} <- Enum.take(sizes, 3) do  # Just first 3 sizes
      data = :crypto.strong_rand_bytes(size)
      
      {prepare_time, {:ok, prepared}} = :timer.tc(fn ->
        FileTransmission.prepare_for_transmission(data, session)
      end)
      
      {receive_time, {:ok, _received}} = :timer.tc(fn ->
        FileTransmission.receive_transmission(
          prepared.chunks,
          prepared.metadata.content_hash,
          session
        )
      end)
      
      prepare_ms = Float.round(prepare_time / 1000, 2)
      receive_ms = Float.round(receive_time / 1000, 2)
      
      IO.puts("#{label}\t\t#{prepare_ms}ms\t\t#{receive_ms}ms")
    end
    
    # Concurrent operations
    IO.puts("\nConcurrent Operations (50 x 10KB):")
    IO.puts("-" |> String.duplicate(50))
    
    data = :crypto.strong_rand_bytes(10_240)
    
    {seq_time, _} = :timer.tc(fn ->
      for _ <- 1..50 do
        {ciphertext, iv, auth_tag} = Encryption.encrypt(data, key)
        {:ok, _} = Encryption.decrypt(ciphertext, key, iv, auth_tag)
      end
    end)
    
    {conc_time, _} = :timer.tc(fn ->
      tasks = for _ <- 1..50 do
        Task.async(fn ->
          {ciphertext, iv, auth_tag} = Encryption.encrypt(data, key)
          {:ok, _} = Encryption.decrypt(ciphertext, key, iv, auth_tag)
        end)
      end
      
      Task.await_many(tasks)
    end)
    
    seq_ms = Float.round(seq_time / 1000, 2)
    conc_ms = Float.round(conc_time / 1000, 2)
    speedup = Float.round(seq_time / conc_time, 2)
    
    IO.puts("Sequential: #{seq_ms}ms (#{Float.round(seq_ms / 50, 2)}ms per op)")
    IO.puts("Concurrent: #{conc_ms}ms (#{Float.round(conc_ms / 50, 2)}ms per op)")
    IO.puts("Speedup: #{speedup}x")
    
    IO.puts("\nBenchmark complete!\n")
    
    # Test passed if we got here
    assert true
  end
end