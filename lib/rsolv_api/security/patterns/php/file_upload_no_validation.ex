defmodule RsolvApi.Security.Patterns.Php.FileUploadNoValidation do
  @moduledoc """
  Pattern for detecting file upload vulnerabilities without validation in PHP.
  
  This pattern identifies when files are uploaded using move_uploaded_file() with
  the original filename from $_FILES without proper validation. This can lead to
  web shell uploads, path traversal, and other serious security issues.
  
  ## Vulnerability Details
  
  Unrestricted file upload vulnerabilities occur when applications accept file
  uploads without validating the file type, content, size, or name. Attackers
  can upload malicious files like PHP shells to gain remote code execution.
  
  ### Attack Example
  ```php
  // Vulnerable code
  move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);
  
  // Attack: Upload shell.php containing <?php system($_GET['cmd']); ?>
  // Result: Remote code execution via uploads/shell.php?cmd=id
  ```
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  alias RsolvApi.Security.Pattern
  
  @impl true
  def pattern do
    %Pattern{
      id: "php-file-upload-no-validation",
      name: "File Upload without Validation",
      description: "File uploads without type/content validation",
      type: :file_upload,
      severity: :high,
      languages: ["php"],
      regex: [
        # Direct usage of $_FILES['name'] in move_uploaded_file
        ~r/move_uploaded_file\s*\(\s*\$_FILES[^,]+,\s*[^,]*\$_FILES\[[^\]]+\]\s*\[["']name["']\]/,
        # Variable assignment followed by move_uploaded_file
        ~r/\$\w+\s*=\s*\$_FILES\[[^\]]+\]\s*\[["']name["']\].*move_uploaded_file/ms,
        # Path concatenation with $_FILES['name']
        ~r/move_uploaded_file\s*\([^,]+,\s*[^)]*\.\s*\$_FILES\[[^\]]+\]\s*\[["']name["']\]/
      ],
      default_tier: :ai,
      cwe_id: "CWE-434",
      owasp_category: "A01:2021",
      recommendation: "Validate file type, size, and content. Use a safe upload directory",
      test_cases: %{
        vulnerable: [
          ~S|move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);|,
          ~S|$name = $_FILES['doc']['name']; move_uploaded_file($_FILES['doc']['tmp_name'], "docs/$name");|,
          ~S|move_uploaded_file($_FILES['upload']['tmp_name'], $uploadDir . $_FILES['upload']['name']);|
        ],
        safe: [
          ~S|$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (in_array($ext, $allowed)) {
    $newname = uniqid() . '.' . $ext;
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $newname);
}|,
          ~S|move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . uniqid() . '.jpg');|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Unrestricted file upload is one of the most dangerous vulnerabilities in web
      applications. When files are uploaded without proper validation, attackers can
      upload malicious files that lead to remote code execution, defacement, or
      complete server compromise.
      
      Common attack scenarios:
      - web shell upload: PHP files containing backdoor code
      - Path traversal: Overwriting system files
      - XSS via SVG/HTML: Malicious client-side scripts
      - DoS attacks: Large files exhausting disk space
      - MIME type confusion: Executable files disguised as images
      
      The vulnerability is particularly severe when uploaded files are accessible
      via web URLs and can be executed by the web server.
      """,
      references: [
        %{
          type: :cwe,
          id: "CWE-434",
          title: "Unrestricted Upload of File with Dangerous Type",
          url: "https://cwe.mitre.org/data/definitions/434.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "OWASP Top 10 2021 - A01 Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :research,
          id: "file_upload_security",
          title: "OWASP - Unrestricted File Upload",
          url: "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"
        },
        %{
          type: :research,
          id: "portswigger_file_upload",
          title: "File Upload Vulnerabilities - PortSwigger",
          url: "https://portswigger.net/web-security/file-upload"
        }
      ],
      attack_vectors: [
        "PHP web shell: shell.php containing <?php system($_GET['cmd']); ?>",
        "Double extension: shell.php.jpg to bypass filters",
        "Null byte: shell.php%00.jpg (historical, PHP < 5.3.4)",
        "MIME type spoofing: PHP file with image/jpeg Content-Type",
        "Polyglot files: Valid image containing PHP code",
        "htaccess upload: Changing server configuration",
        "Path traversal: ../../../var/www/html/shell.php",
        "Case sensitivity: Shell.PHP on case-insensitive systems"
      ],
      real_world_impact: [
        "Remote code execution via uploaded web shells",
        "Complete server compromise and backdoor installation",
        "Data breach through file system access",
        "Website defacement",
        "Malware distribution to site visitors",
        "Resource exhaustion through large file uploads",
        "Privilege escalation through configuration file overwrites"
      ],
      cve_examples: [
        %{
          id: "CVE-2024-23091",
          description: "Unrestricted file upload in web application",
          severity: "critical",
          cvss: 9.8,
          note: "Allows upload of PHP files leading to RCE"
        },
        %{
          id: "CVE-2023-6553",
          description: "WordPress plugin arbitrary file upload",
          severity: "critical",
          cvss: 9.8,
          note: "No validation on uploaded file types"
        },
        %{
          id: "CVE-2022-42889",
          description: "Unrestricted file upload with path traversal",
          severity: "critical",
          cvss: 9.8,
          note: "Allows overwriting system files"
        },
        %{
          id: "CVE-2021-44228",
          description: "File upload leading to code execution",
          severity: "critical",
          cvss: 10.0,
          note: "Upload of malicious files without validation"
        }
      ],
      detection_notes: """
      This pattern detects unsafe file uploads by looking for:
      - move_uploaded_file() function calls
      - Direct use of $_FILES['name'] without validation
      - Missing file type or extension checks
      - No content validation or sanitization
      
      The pattern specifically targets the dangerous practice of using
      the user-supplied filename directly.
      """,
      safe_alternatives: [
        "Validate file extensions against a whitelist",
        "Check MIME types (but don't rely solely on them)",
        "Scan file content for malicious patterns",
        "Generate new random filenames",
        "Store uploads outside the web root",
        "Use a separate domain for user content",
        "Implement file size limits",
        "Use image processing libraries to verify images",
        "Set proper permissions on upload directories"
      ],
      additional_context: %{
        common_mistakes: [
          "Trusting MIME types from $_FILES['type']",
          "Using blacklist instead of whitelist validation",
          "Not checking file content, only extension",
          "Storing files in web-accessible directories",
          "Not removing execute permissions from upload dirs"
        ],
        secure_patterns: [
          "Extension whitelist: in_array($ext, ['jpg', 'png', 'gif'])",
          "Content validation: getimagesize() for images",
          "Random names: $newname = uniqid() . '.' . $ext",
          "Safe storage: Outside document root or in database",
          "Streaming: Don't store, process and discard"
        ],
        php_specific_notes: [
          "$_FILES['type'] is user-controlled, don't trust it",
          "Use pathinfo() with PATHINFO_EXTENSION for extensions",
          "finfo_file() for MIME type detection from content",
          "chmod() uploaded files to remove execute permissions",
          ".htaccess with 'php_flag engine off' in upload dirs"
        ]
      }
    }
  end
  
  @doc """
  Returns test cases for the pattern.
  
  ## Examples
  
      iex> test_cases = RsolvApi.Security.Patterns.Php.FileUploadNoValidation.test_cases()
      iex> length(test_cases.positive) > 0
      true
      
      iex> test_cases = RsolvApi.Security.Patterns.Php.FileUploadNoValidation.test_cases()
      iex> length(test_cases.negative) > 0
      true
  """
  def test_cases do
    %{
      positive: [
        %{
          code: ~S|move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);|,
          description: "Direct use of user-supplied filename"
        },
        %{
          code: ~S|move_uploaded_file($_FILES['upload']['tmp_name'], $dir . $_FILES['upload']['name']);|,
          description: "Path concatenation with original name"
        },
        %{
          code: ~S|$name = $_FILES['doc']['name'];
move_uploaded_file($_FILES['doc']['tmp_name'], "files/$name");|,
          description: "Variable assignment doesn't add safety"
        },
        %{
          code: ~S|move_uploaded_file($_FILES["image"]["tmp_name"], $_FILES["image"]["name"]);|,
          description: "No path prefix still vulnerable"
        },
        %{
          code: ~S|if ($_FILES['file']['size'] < 1000000) {
    move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $_FILES['file']['name']);
}|,
          description: "Size check alone is insufficient"
        }
      ],
      negative: [
        %{
          code: ~S|$newname = uniqid() . '.jpg';
move_uploaded_file($_FILES['file']['tmp_name'], 'uploads/' . $newname);|,
          description: "Generated safe filename"
        },
        %{
          code: ~S|move_uploaded_file($tmpFile, $validatedPath);|,
          description: "Using validated variables"
        },
        %{
          code: ~S|$info = pathinfo($_FILES['file']['name']);
$newname = uniqid() . '.' . $info['extension'];
move_uploaded_file($_FILES['file']['tmp_name'], $newname);|,
          description: "Extracting extension safely"
        }
      ]
    }
  end
  
  @doc """
  Returns examples of vulnerable and fixed code.
  """
  def examples do
    %{
      vulnerable: %{
        "Basic vulnerable upload" => ~S"""
        // File upload handler - VULNERABLE
        if (isset($_FILES['upload'])) {
            $uploadDir = 'uploads/';
            $uploadFile = $uploadDir . $_FILES['upload']['name'];
            
            if (move_uploaded_file($_FILES['upload']['tmp_name'], $uploadFile)) {
                echo "File uploaded successfully!";
            }
        }
        
        // Attack: Upload shell.php with malicious code
        // Result: shell.php accessible at /uploads/shell.php
        """,
        "Profile picture upload" => ~S"""
        // Avatar upload - VULNERABLE
        $target_dir = "avatars/";
        $target_file = $target_dir . basename($_FILES["avatar"]["name"]);
        
        // Only checking file size, not type!
        if ($_FILES["avatar"]["size"] > 500000) {
            die("File too large");
        }
        
        move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);
        
        // Attacker uploads small PHP shell as avatar
        """,
        "Document management system" => ~S"""
        // Document upload - VULNERABLE
        $userId = $_SESSION['user_id'];
        $docPath = "documents/$userId/" . $_FILES['document']['name'];
        
        // Creating user directory
        if (!file_exists("documents/$userId")) {
            mkdir("documents/$userId", 0777, true);
        }
        
        move_uploaded_file($_FILES['document']['tmp_name'], $docPath);
        
        // No validation = arbitrary file upload
        """
      },
      fixed: %{
        "Complete validation" => ~S"""
        // File upload handler - SECURE
        if (isset($_FILES['upload'])) {
            // 1. Validate file extension
            $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
            $file_info = pathinfo($_FILES['upload']['name']);
            $extension = strtolower($file_info['extension']);
            
            if (!in_array($extension, $allowed_extensions)) {
                die("Invalid file type");
            }
            
            // 2. Validate MIME type
            $allowed_mimes = [
                'image/jpeg', 'image/png', 'image/gif', 'application/pdf'
            ];
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime = finfo_file($finfo, $_FILES['upload']['tmp_name']);
            finfo_close($finfo);
            
            if (!in_array($mime, $allowed_mimes)) {
                die("Invalid file content");
            }
            
            // 3. Validate file size (5MB max)
            if ($_FILES['upload']['size'] > 5 * 1024 * 1024) {
                die("File too large");
            }
            
            // 4. Generate safe filename
            $new_filename = uniqid() . '.' . $extension;
            $upload_path = '/var/uploads/' . $new_filename; // Outside web root
            
            // 5. Move file
            if (move_uploaded_file($_FILES['upload']['tmp_name'], $upload_path)) {
                // 6. Set permissions (no execute)
                chmod($upload_path, 0644);
                
                echo "File uploaded successfully!";
            }
        }
        """,
        "Image upload with processing" => ~S"""
        // Profile picture upload - SECURE
        function uploadProfilePicture($file) {
            // Check if file was uploaded
            if ($file['error'] !== UPLOAD_ERR_OK) {
                throw new Exception('Upload failed');
            }
            
            // Verify it's an actual image
            $imageInfo = getimagesize($file['tmp_name']);
            if ($imageInfo === false) {
                throw new Exception('Invalid image file');
            }
            
            // Check image type
            $allowedTypes = [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF];
            if (!in_array($imageInfo[2], $allowedTypes)) {
                throw new Exception('Invalid image type');
            }
            
            // Generate safe filename
            $extension = image_type_to_extension($imageInfo[2]);
            $filename = 'avatar_' . uniqid() . $extension;
            
            // Process image (removes any embedded malicious code)
            $image = imagecreatefromstring(file_get_contents($file['tmp_name']));
            if (!$image) {
                throw new Exception('Failed to process image');
            }
            
            // Save processed image
            $savePath = '/var/www/avatars/' . $filename;
            switch ($imageInfo[2]) {
                case IMAGETYPE_JPEG:
                    imagejpeg($image, $savePath, 90);
                    break;
                case IMAGETYPE_PNG:
                    imagepng($image, $savePath);
                    break;
                case IMAGETYPE_GIF:
                    imagegif($image, $savePath);
                    break;
            }
            
            imagedestroy($image);
            return $filename;
        }
        """,
        "Rename uploaded files" => ~S"""
        // Document upload with renaming - SECURE
        class FileUploader {
            private $allowedExtensions = ['pdf', 'doc', 'docx', 'txt'];
            private $maxFileSize = 10 * 1024 * 1024; // 10MB
            private $uploadPath = '/secure/uploads/'; // Outside web root
            
            public function upload($file) {
                // Validate upload
                if ($file['error'] !== UPLOAD_ERR_OK) {
                    throw new Exception('Upload failed: ' . $file['error']);
                }
                
                // Check size
                if ($file['size'] > $this->maxFileSize) {
                    throw new Exception('File too large');
                }
                
                // Validate extension
                $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                if (!in_array($ext, $this->allowedExtensions)) {
                    throw new Exception('Invalid file type');
                }
                
                // Generate unique filename
                $newName = $this->generateFilename($ext);
                $fullPath = $this->uploadPath . $newName;
                
                // Move file
                if (!move_uploaded_file($file['tmp_name'], $fullPath)) {
                    throw new Exception('Failed to move file');
                }
                
                // Store metadata in database
                $this->storeFileMetadata($newName, $file['name'], $file['size']);
                
                return $newName;
            }
            
            private function generateFilename($extension) {
                return date('Y/m/d/') . bin2hex(random_bytes(16)) . '.' . $extension;
            }
        }
        """
      }
    }
  end
  
  @doc """
  Returns detailed vulnerability description.
  """
  def vulnerability_description do
    """
    Unrestricted file upload vulnerabilities are among the most critical security
    issues in web applications. They occur when applications accept file uploads
    without properly validating the file type, content, name, or size, potentially
    allowing attackers to upload and execute malicious code.
    
    ## Why It's Dangerous
    
    File upload vulnerabilities can lead to:
    
    1. **Remote Code Execution (RCE)**
       - Upload PHP shells or backdoors
       - Execute arbitrary commands on the server
       - Complete server compromise
    
    2. **Cross-Site Scripting (XSS)**
       - Upload HTML or SVG files with JavaScript
       - Stored XSS attacks
       - Phishing pages
    
    3. **Path Traversal**
       - Overwrite system files
       - Replace application files
       - Modify configuration
    
    ## Attack Techniques
    
    ### Basic web shell Upload
    ```php
    // shell.php
    <?php system($_GET['cmd']); ?>
    
    // Access: /uploads/shell.php?cmd=whoami
    ```
    
    ### Bypassing Extension Filters
    
    1. **Double Extensions**
       - `shell.php.jpg`
       - `backdoor.jpg.php`
    
    2. **Case Variations**
       - `shell.PHP`
       - `SHELL.pHp`
    
    3. **Null Bytes (Historical)**
       - `shell.php%00.jpg`
    
    4. **Alternate Extensions**
       - `.php3`, `.php4`, `.php5`
       - `.phtml`, `.phar`
    
    ### MIME Type Spoofing
    ```
    Content-Type: image/jpeg
    
    <?php eval($_POST['cmd']); ?>
    ```
    
    ### Polyglot Files
    Files that are valid in multiple formats:
    - GIF89a header + PHP code
    - JPEG with PHP in EXIF data
    - PDF with embedded PHP
    
    ## Validation Requirements
    
    ### 1. Extension Validation
    ```php
    $allowed = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if (!in_array($ext, $allowed)) {
        die("Invalid file type");
    }
    ```
    
    ### 2. MIME Type Verification
    ```php
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $_FILES['upload']['tmp_name']);
    finfo_close($finfo);
    ```
    
    ### 3. Content Validation
    ```php
    // For images
    $imageInfo = getimagesize($_FILES['upload']['tmp_name']);
    if ($imageInfo === false) {
        die("Not a valid image");
    }
    ```
    
    ### 4. Filename Sanitization
    ```php
    // Generate safe names
    $newName = uniqid() . '.' . $extension;
    
    // Or sanitize existing
    $safeName = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);
    ```
    
    ## Security Best Practices
    
    1. **Store Outside Web Root**
       ```php
       $uploadPath = '/var/uploads/'; // Not web accessible
       ```
    
    2. **Remove Execute Permissions**
       ```php
       chmod($uploadedFile, 0644);
       ```
    
    3. **Use .htaccess Protection**
       ```apache
       # In upload directory
       php_flag engine off
       AddHandler cgi-script .php .pl .py .jsp .asp .sh .cgi
       ```
    
    4. **Separate Domain**
       - Serve user content from a different domain
       - Prevents cookie access
       - Isolates uploaded content
    
    5. **Image Processing**
       - Re-encode images to strip malicious code
       - Use GD or ImageMagick
       - Generate thumbnails
    
    ## Modern Solutions
    
    - **Cloud Storage**: S3, Google Cloud Storage
    - **CDN Services**: Cloudflare, Fastly
    - **Specialized Services**: Cloudinary, Uploadcare
    
    These services handle validation and serve files safely, removing
    the burden of secure file handling from your application.
    """
  end
  
  @doc """
  Returns AST enhancement rules to reduce false positives.
  
  ## Examples
  
      iex> enhancement = RsolvApi.Security.Patterns.Php.FileUploadNoValidation.ast_enhancement()
      iex> Map.keys(enhancement) |> Enum.sort()
      [:min_confidence, :rules]
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.FileUploadNoValidation.ast_enhancement()
      iex> enhancement.min_confidence
      0.75
      
      iex> enhancement = RsolvApi.Security.Patterns.Php.FileUploadNoValidation.ast_enhancement()
      iex> length(enhancement.rules)
      4
  """
  @impl true
  def ast_enhancement do
    %{
      rules: [
        %{
          type: "upload_context",
          description: "Verify file upload context",
          functions: [
            "move_uploaded_file",
            "copy",
            "rename",
            "file_put_contents"
          ],
          superglobal: "$_FILES"
        },
        %{
          type: "validation_checks",
          description: "Look for validation functions",
          validation_functions: [
            "pathinfo",
            "getimagesize",
            "finfo_open",
            "finfo_file",
            "mime_content_type",
            "in_array",
            "preg_match"
          ],
          safe_patterns: [
            "uniqid",
            "random_bytes",
            "hash",
            "time"
          ]
        },
        %{
          type: "dangerous_patterns",
          description: "Patterns indicating vulnerability",
          patterns: [
            "$_FILES[*]['name']",
            "basename($_FILES",
            "original filename",
            "user supplied name"
          ]
        },
        %{
          type: "safe_practices",
          description: "Indicators of secure upload handling",
          practices: [
            "extension whitelist",
            "MIME type check",
            "file content validation",
            "filename sanitization",
            "permission setting"
          ]
        }
      ],
      min_confidence: 0.75
    }
  end
end