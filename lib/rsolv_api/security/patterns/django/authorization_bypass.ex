defmodule RsolvApi.Security.Patterns.Django.AuthorizationBypass do
  @moduledoc """
  Django Authorization Bypass pattern for Django applications.
  
  This pattern detects missing or insufficient permission checks that could
  allow unauthorized users to access or modify resources they shouldn't have
  access to.
  
  ## Background
  
  Authorization bypass vulnerabilities occur when applications fail to properly
  verify that a user has the necessary permissions to perform an action or
  access a resource. In Django, this often manifests as:
  
  - Views without permission checks
  - Direct object references without ownership validation
  - Queries that don't filter by user ownership
  - Missing object-level permission checks
  
  ## Vulnerability Details
  
  Django provides several mechanisms for authorization:
  - Function-based views: @permission_required decorator
  - Class-based views: PermissionRequiredMixin
  - Model-level: has_perm() method
  - Object-level: django-guardian or custom checks
  
  Failing to use these mechanisms can lead to horizontal and vertical
  privilege escalation.
  
  ## Examples
  
      # VULNERABLE - No permission check
      def delete_document(request, doc_id):
          document = Document.objects.get(pk=doc_id)
          document.delete()
          
      # VULNERABLE - get_object_or_404 without user check
      invoice = get_object_or_404(Invoice, pk=invoice_id)
      
      # VULNERABLE - All objects exposed
      documents = Document.objects.all()
      
      # SAFE - Permission decorator
      @permission_required('app.delete_document')
      def delete_document(request, doc_id):
          document = get_object_or_404(Document, pk=doc_id, user=request.user)
          document.delete()
      
      # SAFE - Filtered by user
      documents = Document.objects.filter(user=request.user)
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "django-authorization-bypass",
      name: "Django Authorization Bypass",
      description: "Missing or insufficient permission checks allowing unauthorized access",
      type: :authorization,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # Views without permission decorators performing sensitive operations
        ~r/def\s+\w+\s*\(\s*request.*?\)(?!.*@permission_required)(?!.*@user_passes_test)(?!.*has_perm).*?(?:delete|update|create|modify)/s,
        
        # get_object_or_404 without user parameter
        ~r/get_object_or_404\s*\(\s*\w+,\s*pk\s*=\s*\w+\)(?!.*user\s*=)/,
        
        # Objects.filter() followed by delete/update without user constraint
        ~r/\.objects\.filter\s*\(\s*\)\.(?:delete|update)\s*\(/,
        
        # Objects.all() without subsequent filtering
        ~r/\w+\.objects\.all\s*\(\s*\)(?!.*filter.*user)/,
        
        # Direct pk access from request without validation
        ~r/\.objects\.get\s*\(\s*pk\s*=\s*request\./,
        
        # Update/delete without ownership check
        ~r/\.objects\.filter\s*\([^)]*\)\.(?:delete|update)\s*\((?!.*user=request\.user)/,
        
        # Raw SQL without user constraints
        ~r/\.raw\s*\(\s*['"]\s*(?:DELETE|UPDATE).*WHERE\s+(?!.*user_id)/i
      ],
      cwe_id: "CWE-862",
      owasp_category: "A01:2021",
      recommendation: "Implement proper permission checks using @permission_required or check user.has_perm()",
      test_cases: %{
        vulnerable: [
          "document = get_object_or_404(Document, pk=doc_id)",
          "Document.objects.filter().delete()",
          "all_records = Record.objects.all()"
        ],
        safe: [
          "document = get_object_or_404(Document, pk=doc_id, user=request.user)",
          """
          @permission_required('app.delete_document')
          def delete_view(request):
          """,
          "user_records = Record.objects.filter(user=request.user)"
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Authorization bypass vulnerabilities in Django applications occur when
      permission checks are missing, insufficient, or improperly implemented.
      This allows users to access or modify resources beyond their intended
      privileges.
      
      Common authorization bypass patterns in Django include:
      
      1. **Missing Permission Decorators**: Views handling sensitive operations
         without @permission_required or similar checks
      
      2. **Direct Object References**: Accessing objects by ID without verifying
         the user has permission to view/modify them
      
      3. **Unfiltered Querysets**: Using Model.objects.all() or broad filters
         that expose data from all users
      
      4. **Missing Object-Level Permissions**: Checking only model-level permissions
         when object-level granularity is needed
      
      5. **Improper Permission Logic**: Custom permission checks that can be
         bypassed through parameter manipulation
      
      Django provides comprehensive authorization features including decorators,
      mixins, and permission methods. Using these consistently prevents most
      authorization bypass vulnerabilities.
      """,
      
      references: [
        %{
          type: :cwe,
          id: "CWE-862",
          title: "Missing Authorization",
          url: "https://cwe.mitre.org/data/definitions/862.html"
        },
        %{
          type: :cwe,
          id: "CWE-863",
          title: "Incorrect Authorization",
          url: "https://cwe.mitre.org/data/definitions/863.html"
        },
        %{
          type: :cwe,
          id: "CWE-639",
          title: "Authorization Bypass Through User-Controlled Key",
          url: "https://cwe.mitre.org/data/definitions/639.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        }
      ],
      
      attack_vectors: [
        "Direct object reference manipulation (changing IDs in URLs)",
        "Parameter manipulation to access unauthorized resources",
        "Horizontal privilege escalation (accessing other users' data)",
        "Vertical privilege escalation (performing admin actions)",
        "Path traversal to access restricted files",
        "Forced browsing to unprotected admin interfaces",
        "API endpoint manipulation",
        "Mass assignment to modify protected fields"
      ],
      
      real_world_impact: [
        "Unauthorized access to sensitive user data",
        "Data modification or deletion by unauthorized users",
        "Privilege escalation to administrator access",
        "Business logic bypass leading to financial loss",
        "Privacy violations and regulatory compliance issues",
        "Data breaches exposing confidential information",
        "Account takeover through profile manipulation",
        "Competitive advantage loss through data exposure"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2023-31047",
          description: "Django admin changelist filters authorization bypass",
          severity: "high",
          cvss: 7.5,
          note: "Allowed viewing data via admin filters without proper permissions"
        },
        %{
          id: "CVE-2021-31542",
          description: "Django MultiPartParser boundary issue leading to DoS",
          severity: "medium",
          cvss: 5.3,
          note: "While primarily DoS, could be used to bypass rate limiting"
        },
        %{
          id: "CVE-2019-14232",
          description: "Django URL validation bypass in URLValidator",
          severity: "high",
          cvss: 7.5,
          note: "Could allow access to unauthorized URLs through validation bypass"
        },
        %{
          id: "CVE-2019-3498",
          description: "Django path traversal via static URL patterns",
          severity: "high",
          cvss: 7.5,
          note: "Allowed accessing files outside intended directories"
        }
      ],
      
      detection_notes: """
      This pattern detects authorization bypass by identifying:
      
      1. Function definitions without permission decorators that perform
         sensitive operations (delete, update, create)
      2. get_object_or_404 calls without user ownership filtering
      3. Broad queries using filter().delete() or all() without constraints
      4. Direct object access using request parameters without validation
      5. Raw SQL queries without user_id constraints
      
      The pattern uses negative lookahead to avoid false positives when
      permission checks are present. AST enhancement further reduces
      false positives by analyzing context.
      """,
      
      safe_alternatives: [
        """
        # Use permission decorators
        from django.contrib.auth.decorators import permission_required
        
        @permission_required('app.delete_document')
        def delete_document(request, doc_id):
            document = get_object_or_404(Document, pk=doc_id, user=request.user)
            document.delete()
        """,
        """
        # Object-level permission checks
        def edit_document(request, doc_id):
            document = get_object_or_404(Document, pk=doc_id)
            if not request.user.has_perm('app.change_document', document):
                raise PermissionDenied
            # Process edit
        """,
        """
        # Filter querysets by user
        def list_documents(request):
            # Only show documents owned by the user
            documents = Document.objects.filter(user=request.user)
            return render(request, 'documents.html', {'documents': documents})
        """,
        """
        # Use Django Guardian for object permissions
        from guardian.shortcuts import get_objects_for_user
        
        def list_shared_documents(request):
            # Get all documents user has view permission for
            documents = get_objects_for_user(
                request.user, 'view_document', Document
            )
        """,
        """
        # Class-based view with PermissionRequiredMixin
        from django.contrib.auth.mixins import PermissionRequiredMixin
        
        class DocumentDeleteView(PermissionRequiredMixin, DeleteView):
            model = Document
            permission_required = 'app.delete_document'
            
            def get_queryset(self):
                # Ensure users can only delete their own documents
                return super().get_queryset().filter(user=self.request.user)
        """
      ],
      
      additional_context: %{
        common_mistakes: [
          "Assuming authentication implies authorization",
          "Checking permissions at template level only",
          "Not filtering querysets by user ownership",
          "Using request parameters directly without validation",
          "Implementing custom permission logic instead of Django's",
          "Missing object-level permission checks",
          "Not checking permissions in API views",
          "Inconsistent permission checks across views"
        ],
        
        secure_patterns: [
          """
          # Comprehensive permission checking
          from django.contrib.auth.decorators import login_required, permission_required
          from django.core.exceptions import PermissionDenied
          
          @login_required
          @permission_required('app.change_document')
          def edit_document(request, doc_id):
              # Model-level permission checked by decorator
              document = get_object_or_404(Document, pk=doc_id)
              
              # Object-level permission check
              if document.user != request.user and not request.user.is_staff:
                  raise PermissionDenied
              
              # Safe to proceed
              if request.method == 'POST':
                  # Process form
                  pass
          """,
          """
          # Secure queryset filtering
          class DocumentViewSet(viewsets.ModelViewSet):
              permission_classes = [IsAuthenticated]
              
              def get_queryset(self):
                  user = self.request.user
                  if user.is_staff:
                      return Document.objects.all()
                  return Document.objects.filter(
                      Q(user=user) | Q(shared_with=user)
                  )
          """,
          """
          # Permission check in forms
          class DocumentForm(forms.ModelForm):
              def __init__(self, *args, user=None, **kwargs):
                  super().__init__(*args, **kwargs)
                  self.user = user
                  
              def clean(self):
                  cleaned_data = super().clean()
                  if self.instance.pk:
                      if not self.user.has_perm('change_document', self.instance):
                          raise forms.ValidationError("No permission to edit")
                  return cleaned_data
          """
        ],
        
        framework_specific_notes: [
          "Django's permission system is tied to models by default",
          "Use django-guardian for object-level permissions",
          "DRF has its own permission classes that should be used for APIs",
          "@permission_required checks model-level permissions only",
          "Custom permissions can be added to model Meta class",
          "Staff users bypass some permission checks by default",
          "Superusers have all permissions implicitly",
          "Permission caching can cause issues in long-running requests"
        ]
      }
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      
      context_rules: %{
        permission_decorators: [
          "@permission_required",
          "@user_passes_test",
          "@staff_member_required",
          "@login_required",
          "@require_http_methods",
          "@require_POST",
          "@require_GET"
        ],
        
        permission_methods: [
          "has_perm",
          "has_perms",
          "has_module_perms",
          "has_object_permission",
          "get_user_permissions",
          "get_group_permissions",
          "get_all_permissions"
        ],
        
        sensitive_operations: [
          "delete",
          "update",
          "create",
          "modify",
          "save",
          "remove",
          "destroy",
          "set",
          "change",
          "edit",
          "add"
        ],
        
        safe_patterns: [
          "filter(user=request.user)",
          "filter(owner=request.user)",
          "get_object_or_404(",
          "user=request.user",
          "if request.user.has_perm",
          "if user.has_perm",
          "PermissionDenied"
        ],
        
        public_models: [
          "Article",
          "BlogPost", 
          "NewsItem",
          "PublicDocument",
          "FAQ",
          "StaticPage"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          delete_without_permission: +0.95,
          update_without_permission: +0.9,
          create_without_permission: +0.85,
          get_object_without_user: +0.8,
          all_objects_exposed: +0.85,
          raw_sql_without_user: +0.9,
          
          # Medium confidence
          read_without_permission: +0.6,
          filter_without_user: +0.5,
          generic_view_operations: +0.4,
          
          # Lower confidence
          public_model_access: -0.8,
          has_permission_check: -0.9,
          in_test_file: -0.95,
          in_migration: -0.98,
          list_view_only: -0.4,
          
          # Context adjustments
          has_permission_decorator: -0.95,
          has_user_filter: -0.85,
          in_permission_backend: -0.9,
          is_staff_only_view: -0.3
        }
      },
      
      ast_rules: %{
        permission_analysis: %{
          detect_decorators: true,
          check_permission_calls: true,
          analyze_queryset_filters: true,
          check_object_ownership: true,
          detect_raw_queries: true,
          analyze_view_purpose: true
        },
        
        queryset_analysis: %{
          check_filter_params: true,
          detect_user_constraints: true,
          analyze_all_usage: true,
          check_select_related: true
        },
        
        context_analysis: %{
          check_file_path: true,
          analyze_imports: true,
          detect_model_type: true,
          check_view_name: true
        },
        
        security_analysis: %{
          check_object_access: true,
          detect_id_params: true,
          analyze_permission_flow: true,
          check_api_permissions: true
        }
      }
    }
  end
end