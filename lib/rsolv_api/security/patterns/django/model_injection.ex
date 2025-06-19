defmodule RsolvApi.Security.Patterns.Django.ModelInjection do
  @moduledoc """
  Django Model Injection pattern for Django applications.
  
  This pattern detects injection vulnerabilities in Django model operations where
  untrusted user input is directly used to manipulate model fields, potentially
  allowing attackers to modify unintended fields or bypass validation.
  
  ## Background
  
  Model injection (mass assignment) vulnerabilities occur when applications
  directly use user-supplied data to create or update model instances without
  proper field validation or whitelisting. This can lead to:
  
  - Privilege escalation by modifying admin/staff flags
  - Data corruption by changing protected fields
  - Business logic bypass by manipulating state fields
  - Security control bypass by modifying permission fields
  
  ## Vulnerability Details
  
  Common model injection patterns include:
  - Using **request.POST or **request.data with model operations
  - Dynamic attribute setting with setattr() on user input
  - Direct field assignment from unvalidated sources
  - Missing field restrictions in forms or serializers
  
  ## Examples
  
      # VULNERABLE - Mass assignment with all POST data
      def create_user(request):
          user = User.objects.create(**request.POST)
          
      # VULNERABLE - Dynamic attribute setting
      for field, value in request.POST.items():
          setattr(model, field, value)
          
      # VULNERABLE - Unrestricted update
      Profile.objects.filter(id=id).update(**request.data)
      
      # SAFE - Explicit field assignment
      user = User.objects.create(
          username=request.POST.get('username'),
          email=request.POST.get('email')
      )
      
      # SAFE - Using ModelForm with fields restriction
      class UserForm(ModelForm):
          class Meta:
              model = User
              fields = ['username', 'email']  # Only these fields
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "django-model-injection",
      name: "Django Model Injection",
      description: "Injection vulnerabilities in model operations",
      type: :injection,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # .objects.create(**request.POST/data/FILES)
        ~r/\.objects\.create\s*\(\s*\*\*request\./,
        
        # .objects.update(**request.POST/data/FILES) or .filter().update(**request.)
        ~r/\.(?:objects\.)?update\s*\(\s*\*\*request\./,
        
        # .save(update_fields=request.)
        ~r/\.save\s*\(\s*update_fields\s*=\s*request\./,
        
        # setattr with request data - more flexible pattern
        ~r/setattr\s*\(.*?,\s*(?:request\.|field)/,
        
        # getattr with request data (can lead to information disclosure)
        ~r/getattr\s*\(\s*\w+,\s*request\./
      ],
      cwe_id: "CWE-74",
      owasp_category: "A03:2021",
      recommendation: "Validate and whitelist fields before model operations",
      test_cases: %{
        vulnerable: [
          ~s|User.objects.create(**request.POST)|,
          ~s|model.save(update_fields=request.POST.getlist('fields'))|,
          ~s|setattr(user, request.POST['field'], value)|
        ],
        safe: [
          ~s|User.objects.create(
    username=request.POST.get('username'),
    email=request.POST.get('email')
)|,
          ~s|allowed_fields = ['name', 'email']
model.save(update_fields=[f for f in fields if f in allowed_fields])|,
          ~s|class UserForm(ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email']|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Model injection vulnerabilities in Django occur when untrusted user input
      is directly used to manipulate model instances without proper validation
      or field whitelisting. This is similar to mass assignment vulnerabilities
      in other frameworks.
      
      The vulnerability typically manifests in several ways:
      
      1. **Mass Assignment via kwargs**: Using **request.POST or **request.data
         directly in model operations allows attackers to set any model field
      
      2. **Dynamic Attribute Setting**: Using setattr() with user-controlled
         field names enables arbitrary field modification
      
      3. **Unrestricted Updates**: Bulk update operations without field
         restrictions can modify protected fields
      
      4. **Form/Serializer Misconfiguration**: Using fields = '__all__' or
         missing field restrictions exposes all model fields
      
      Django provides several mechanisms to prevent these vulnerabilities:
      - ModelForm with explicit fields list
      - DRF Serializers with field restrictions
      - Manual field validation and whitelisting
      - Read-only fields in models
      
      However, developers sometimes bypass these protections for convenience,
      creating security vulnerabilities.
      """,
      
      references: [
        %{
          type: :cwe,
          id: "CWE-74",
          title: "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
          url: "https://cwe.mitre.org/data/definitions/74.html"
        },
        %{
          type: :cwe,
          id: "CWE-915",
          title: "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
          url: "https://cwe.mitre.org/data/definitions/915.html"
        },
        %{
          type: :owasp,
          id: "A03:2021",
          title: "Injection",
          url: "https://owasp.org/Top10/A03_2021-Injection/"
        },
        %{
          type: :owasp,
          id: "Mass Assignment",
          title: "Mass Assignment Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
        },
        %{
          type: :semgrep,
          id: "mass-assignment",
          title: "Django Mass Assignment Rule",
          url: "https://semgrep.dev/playground/r/PkTnpo/python.django.security.injection.mass-assignment.mass-assignment"
        }
      ],
      
      attack_vectors: [
        "Mass assignment through parameter manipulation",
        "Adding admin/staff privileges via is_staff/is_superuser fields",
        "Modifying user permissions through groups or user_permissions",
        "Field injection to bypass validation",
        "Changing ownership fields to hijack resources",
        "Bypassing payment systems by modifying balance/credit fields",
        "Altering workflow states to skip approval processes",
        "Modifying timestamps to manipulate audit trails",
        "Injecting malicious data into fields used in templates",
        "Setting internal fields that affect business logic",
        "Overwriting foreign key relationships",
        "Mass assignment via REST API endpoints"
      ],
      
      real_world_impact: [
        "Privilege escalation to administrator access",
        "Unauthorized modification of other users' data",
        "Financial fraud through balance manipulation",
        "Data corruption across related models",
        "Business logic bypass leading to revenue loss",
        "Compliance violations through audit trail manipulation",
        "Account takeover via email/password changes",
        "Information disclosure through hidden field access",
        "Denial of service via resource exhaustion",
        "Supply chain attacks through dependency manipulation"
      ],
      
      cve_examples: [
        %{
          id: "CVE-2022-34265",
          description: "Django SQL injection via Trunc/Extract with user input",
          severity: "critical",
          cvss: 9.8,
          note: "While primarily SQL injection, demonstrates Django input validation issues"
        },
        %{
          id: "CVE-2012-4520",
          description: "Django host header injection allowing cache poisoning",
          severity: "medium",
          cvss: 4.3,
          note: "Shows how unvalidated input can affect Django internals"
        },
        %{
          id: "GitHub Mass Assignment 2012",
          description: "GitHub Public Key mass assignment vulnerability",
          severity: "critical",
          cvss: 9.0,
          note: "Famous mass assignment that allowed adding SSH keys to any repo"
        },
        %{
          id: "CVE-2010-3933",
          description: "Ruby on Rails mass assignment vulnerability",
          severity: "high",
          cvss: 7.5,
          note: "Similar vulnerability pattern affecting Rails applications"
        }
      ],
      
      detection_notes: """
      This pattern detects model injection by identifying:
      
      1. Model.objects.create(**request.XXX) - Direct mass assignment
      2. Model.objects.update(**request.XXX) - Bulk update vulnerability
      3. setattr(model, request.XXX) - Dynamic attribute setting
      4. model.save(update_fields=request.XXX) - Unrestricted field updates
      5. getattr(model, request.XXX) - Potential information disclosure
      
      The pattern focuses on direct use of request data with model operations.
      It may not catch all mass assignment vulnerabilities, especially those
      involving forms or serializers with overly permissive configurations.
      
      AST analysis can reduce false positives by checking for validation
      or whitelisting before the vulnerable operation.
      """,
      
      safe_alternatives: [
        """
        # Explicit field assignment
        def create_user(request):
            user = User.objects.create(
                username=request.POST.get('username'),
                email=request.POST.get('email'),
                first_name=request.POST.get('first_name', '')
            )
            # Never allow direct assignment of is_staff, is_superuser, etc.
            return redirect('user_detail', user.id)
        """,
        """
        # Using ModelForm with restricted fields
        class UserProfileForm(forms.ModelForm):
            class Meta:
                model = UserProfile
                fields = ['bio', 'website', 'location']  # Whitelist allowed fields
                # exclude = ['user', 'is_verified']  # Or blacklist sensitive fields
        
        def update_profile(request):
            form = UserProfileForm(request.POST, instance=request.user.profile)
            if form.is_valid():
                form.save()  # Only whitelisted fields are updated
        """,
        """
        # Manual field validation and whitelisting
        ALLOWED_PROFILE_FIELDS = ['bio', 'website', 'location', 'avatar']
        
        def update_profile_api(request):
            profile = request.user.profile
            
            # Use fields whitelist before processing
            for field in ALLOWED_PROFILE_FIELDS:
                if field in request.data:
                    setattr(profile, field, request.data[field])
            
            profile.full_clean()  # Run model validation
            profile.save(update_fields=ALLOWED_PROFILE_FIELDS)
        """,
        """
        # DRF Serializer with field restrictions
        class UserSerializer(serializers.ModelSerializer):
            class Meta:
                model = User
                fields = ['id', 'username', 'email', 'first_name', 'last_name']
                read_only_fields = ['id', 'username']  # Prevent updates
                extra_kwargs = {
                    'email': {'required': True},
                }
        
        class UserViewSet(viewsets.ModelViewSet):
            serializer_class = UserSerializer
            
            def perform_update(self, serializer):
                # Additional validation before save
                serializer.save()
        """,
        """
        # Property-based protection for sensitive fields
        class User(models.Model):
            _is_staff = models.BooleanField(default=False, db_column='is_staff')
            
            @property
            def is_staff(self):
                return self._is_staff
            
            @is_staff.setter
            def is_staff(self, value):
                # Only allow setting through specific methods
                raise AttributeError("Cannot set is_staff directly")
            
            def promote_to_staff(self, authorized_by):
                # Controlled method with audit trail
                if authorized_by.is_superuser:
                    self._is_staff = True
                    self.save()
                    log_admin_action(authorized_by, self, 'promoted to staff')
        """
      ],
      
      additional_context: %{
        common_mistakes: [
          "Using **request.POST for convenience without validation",
          "Trusting form.cleaned_data without field restrictions",
          "Using ModelForm with fields = '__all__'",
          "Not understanding that exclude still allows other fields",
          "Forgetting that JSONField can contain arbitrary data",
          "Using update() on querysets with user input",
          "Not validating field names in dynamic updates",
          "Mixing trusted and untrusted data in updates"
        ],
        
        secure_patterns: [
          """
          # Comprehensive input validation
          from django.core.exceptions import ValidationError
          
          class SecureModelMixin:
              # Define allowed fields per model
              ALLOWED_USER_FIELDS = []
              
              @classmethod
              def create_from_request(cls, request, allowed_fields=None):
                  fields = allowed_fields or cls.ALLOWED_USER_FIELDS
                  kwargs = {}
                  
                  for field in fields:
                      if field in request.POST:
                          # Validate field exists on model
                          if hasattr(cls, field):
                              kwargs[field] = request.POST[field]
                  
                  instance = cls(**kwargs)
                  instance.full_clean()  # Validate before save
                  instance.save()
                  return instance
          """,
          """
          # Role-based field access
          class FieldAccessMixin:
              def get_allowed_fields(self, user):
                  # Define fields accessible by role
                  if user.is_superuser:
                      return self.ADMIN_FIELDS
                  elif user.is_staff:
                      return self.STAFF_FIELDS
                  else:
                      return self.USER_FIELDS
              
              def update_from_request(self, request):
                  allowed = self.get_allowed_fields(request.user)
                  
                  for field in allowed:
                      if field in request.POST:
                          setattr(self, field, request.POST[field])
                  
                  self.save(update_fields=allowed)
          """,
          """
          # Audit trail for sensitive field changes
          from django.contrib.admin.models import LogEntry, CHANGE
          from django.contrib.contenttypes.models import ContentType
          
          def update_with_audit(model_instance, updates, user):
              # Track what changed
              changes = []
              for field, new_value in updates.items():
                  old_value = getattr(model_instance, field)
                  if old_value != new_value:
                      changes.append(f"{field}: {old_value} → {new_value}")
                      setattr(model_instance, field, new_value)
              
              if changes:
                  model_instance.save()
                  
                  # Log the changes
                  LogEntry.objects.log_action(
                      user_id=user.pk,
                      content_type_id=ContentType.objects.get_for_model(model_instance).pk,
                      object_id=model_instance.pk,
                      object_repr=str(model_instance),
                      action_flag=CHANGE,
                      change_message="; ".join(changes)
                  )
          """
        ],
        
        framework_specific_notes: [
          "Django ModelForms respect model field validators automatically",
          "DRF performs deserialization before validation, catch errors early",
          "Model.clean() is not called on save() by default, use full_clean()",
          "F() expressions bypass Python attribute access, useful for counters",
          "update() on QuerySet bypasses save() and signals",
          "get_or_create() with defaults parameter is safer than create()",
          "Django admin already implements proper field access control",
          "Model properties can provide additional protection layer"
        ]
      }
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      
      context_rules: %{
        model_methods: [
          "objects.create",
          "objects.update", 
          "objects.get_or_create",
          "objects.update_or_create",
          "objects.bulk_create",
          "objects.bulk_update",
          "save",
          "update"
        ],
        
        dangerous_functions: [
          "setattr",
          "getattr",
          "__setattr__",
          "__dict__"
        ],
        
        request_sources: [
          "request.POST",
          "request.GET",
          "request.data",
          "request.FILES",
          "request.META",
          "request.body"
        ],
        
        safe_patterns: [
          "cleaned_data",
          "validated_data",
          "form.save()",
          "serializer.save()"
        ],
        
        field_restrictions: [
          "fields =",
          "exclude =",
          "read_only_fields =",
          "ALLOWED_FIELDS",
          "PROTECTED_FIELDS"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          mass_assignment_create: +0.95,
          mass_assignment_update: +0.9,
          setattr_with_request: +0.95,
          bulk_operations: +0.85,
          
          # Medium confidence
          getattr_with_request: +0.6,
          dict_update: +0.7,
          
          # Lower confidence
          in_test_file: -0.95,
          in_migration: -0.98,
          in_management_command: -0.5,
          
          # Mitigating factors
          in_model_form: -0.8,
          in_serializer: -0.85,
          has_field_validation: -0.7,
          has_permission_check: -0.6,
          uses_cleaned_data: -0.9,
          explicit_field_list: -0.8
        }
      },
      
      ast_rules: %{
        model_analysis: %{
          detect_mass_assignment: true,
          check_field_validation: true,
          analyze_attribute_setting: true,
          check_bulk_operations: true,
          detect_dynamic_fields: true,
          analyze_update_patterns: true
        },
        
        validation_analysis: %{
          check_form_usage: true,
          check_serializer_usage: true,
          detect_validation_bypass: true,
          analyze_field_access: true
        },
        
        request_analysis: %{
          track_request_usage: true,
          check_data_flow: true,
          detect_direct_assignment: true,
          analyze_field_sources: true
        },
        
        security_analysis: %{
          check_permission_decorators: true,
          analyze_user_context: true,
          detect_admin_fields: true,
          check_audit_logging: true
        }
      }
    }
  end
end