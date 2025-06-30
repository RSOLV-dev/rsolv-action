#!/bin/bash
cd /home/dylan/dev/rsolv/RSOLV-api
mix compile
mix run test_ast_detection_flow.exs