defmodule RsolvApi.Security.Patterns.Django.MassAssignment do
  @moduledoc """
  Django Mass Assignment pattern for Django applications.
  
  This pattern detects mass assignment vulnerabilities where untrusted user input
  can modify model fields that should be protected, potentially leading to privilege
  escalation, data manipulation, or security bypass.
  
  ## Background
  
  Mass assignment vulnerabilities occur when web applications automatically bind
  HTTP request parameters to model attributes without proper filtering. In Django,
  this commonly happens with:
  
  - ModelForm with fields = '__all__'
  - Direct model creation/update from request data
  - DRF serializers without field restrictions
  - form.save(commit=False) with additional unvalidated assignments
  
  ## Vulnerability Details
  
  Common mass assignment patterns include:
  - Using fields = '__all__' in ModelForm Meta class
  - Missing field validation in serializers
  - Direct assignment of request data to models
  - Unsafe use of update_or_create with user input
  
  ## Examples
  
      # VULNERABLE - Exposes all model fields
      class UserForm(forms.ModelForm):
          class Meta:
              model = User
              fields = '__all__'  # Dangerous!
              
      # VULNERABLE - No validation on serializer
      serializer = UserSerializer(data=request.data)
      serializer.save()  # Can save any field!
      
      # VULNERABLE - Direct assignment
      User.objects.create(**request.POST.dict())
      
      # SAFE - Explicit field whitelist
      class UserForm(forms.ModelForm):
          class Meta:
              model = User
              fields = ['username', 'email', 'first_name']
              
      # SAFE - Validated serializer
      serializer = UserSerializer(data=request.data)
      if serializer.is_valid():
          serializer.save()
  """
  
  use RsolvApi.Security.Patterns.PatternBase
  
  @impl true
  def pattern do
    %RsolvApi.Security.Pattern{
      id: "django-mass-assignment",
      name: "Django Mass Assignment",
      description: "Mass assignment allowing unauthorized field updates",
      type: :mass_assignment,
      severity: :high,
      languages: ["python"],
      frameworks: ["django"],
      regex: [
        # ModelForm with fields = '__all__' (single or double quotes)
        ~r/ModelForm.*fields\s*=\s*['""]__all__['""]/s,
        
        # fields = "__all__" or fields = '__all__' pattern (direct match)
        ~r/fields\s*=\s*['""]__all__['""]/,
        
        # form.save(commit=False) - often dangerous if not followed by proper save
        ~r/form\.save\s*\(\s*commit\s*=\s*False\s*\)/,
        
        # Serializer without validated_data check or is_valid() check - more flexible pattern
        ~r/serializer.*=.*Serializer\s*\(\s*data\s*=\s*request\./s,
        ~r/serializer\.save\s*\(\s*\)(?<!is_valid)/
      ],
      default_tier: :ai,
      cwe_id: "CWE-915",
      owasp_category: "A01:2021",
      recommendation: "Explicitly define allowed fields in forms and serializers",
      test_cases: %{
        vulnerable: [
          ~s|class UserForm(ModelForm):
    class Meta:
        model = User
        fields = '__all__'|,
          ~s|serializer = UserSerializer(data=request.data)
serializer.save()|
        ],
        safe: [
          ~s|class UserForm(ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email']|,
          ~s|serializer = UserSerializer(data=request.data)
if serializer.is_valid():
    serializer.save()|
        ]
      }
    }
  end
  
  @impl true
  def vulnerability_metadata do
    %{
      description: """
      Mass assignment vulnerabilities in Django occur when applications automatically
      bind HTTP request parameters to model attributes without proper filtering or
      validation. This allows attackers to modify fields that should be protected,
      potentially leading to severe security breaches.
      
      In Django, mass assignment vulnerabilities typically manifest through:
      
      1. **ModelForm with fields = '__all__'**: This exposes every model field
         to user modification, including sensitive fields like is_staff, is_superuser,
         or custom permission fields
      
      2. **Unsafe Serializer Usage**: Django REST Framework serializers without
         proper field restrictions or validation can allow arbitrary field modification
      
      3. **Direct Model Creation**: Using Model.objects.create(**request.POST.dict())
         or similar patterns directly binds all user input to model fields
      
      4. **form.save(commit=False) Misuse**: When combined with additional manual
         field assignments from user input, this can bypass form validation
      
      While not as publicized as the GitHub Rails incident of 2012, Django applications
      are equally susceptible to mass assignment attacks. The framework provides
      protection mechanisms, but developers must actively use them.
      
      The impact varies based on the exposed model and fields but commonly includes:
      - Privilege escalation (modifying is_admin, is_staff fields)
      - Data manipulation (changing ownership, prices, balances)
      - Security bypass (modifying verification status, locked accounts)
      - Business logic bypass (skipping approval workflows, trial limitations)
      """,
      
      references: [
        %{
          type: :cwe,
          id: "CWE-915",
          title: "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
          url: "https://cwe.mitre.org/data/definitions/915.html"
        },
        %{
          type: :owasp,
          id: "A01:2021",
          title: "Broken Access Control",
          url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        },
        %{
          type: :owasp,
          id: "Mass Assignment",
          title: "Mass Assignment Cheat Sheet",
          url: "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
        },
        %{
          type: :django,
          id: "ModelForm Security",
          title: "Django ModelForm Documentation",
          url: "https://docs.djangoproject.com/en/stable/topics/forms/modelforms/#selecting-the-fields-to-use"
        },
        %{
          type: :drf,
          id: "Serializer Fields",
          title: "DRF Serializer Field Handling",
          url: "https://www.django-rest-framework.org/api-guide/serializers/#specifying-which-fields-to-include"
        }
      ],
      
      attack_vectors: [
        "Modifying fields = '__all__' forms to include admin fields",
        "Exploiting form.save(commit=False) to inject additional fields",
        "Sending unexpected fields in serializer data",
        "Adding is_staff=true or is_superuser=true to POST requests",
        "Modifying foreign key relationships to hijack resources",
        "Changing email_verified or account_locked status",
        "Manipulating financial fields (balance, credit, discount)",
        "Altering workflow state fields to skip approvals",
        "Modifying user group memberships or permissions",
        "Changing ownership fields to take over resources"
      ],
      
      real_world_impact: [
        "Privilege escalation to admin or staff access",
        "Unauthorized modification of other users' data",
        "Financial fraud through balance or pricing manipulation",
        "Account takeover by changing email/password fields",
        "Bypassing trial limitations or subscription checks",
        "Data corruption across related models",
        "Breaking business logic and workflows",
        "Compliance violations through audit trail manipulation",
        "Reputation damage from data breaches",
        "Legal liability from unauthorized data access"
      ],
      
      cve_examples: [
        %{
          id: "GitHub Rails 2012",
          description: "Mass assignment vulnerability allowed adding SSH keys to any repository",
          severity: "critical",
          cvss: 9.0,
          note: "While a Rails vulnerability, it raised awareness of mass assignment risks across all frameworks"
        },
        %{
          id: "CVE-2022-34265",
          description: "Django SQL injection via Trunc/Extract with user input",
          severity: "critical",
          cvss: 9.8,
          note: "Demonstrates Django's vulnerability to unvalidated user input"
        },
        %{
          id: "CVE-2010-3933",
          description: "Ruby on Rails mass assignment vulnerability in ActiveRecord",
          severity: "high",
          cvss: 7.5,
          note: "Similar pattern affecting Rails applications, showing framework-agnostic nature"
        },
        %{
          id: "Laravel 2019",
          description: "Mass assignment protection bypass in Eloquent ORM",
          severity: "high",
          cvss: 8.1,
          note: "Shows that modern frameworks still struggle with mass assignment protection"
        }
      ],
      
      detection_notes: """
      This pattern detects mass assignment vulnerabilities by identifying:
      
      1. ModelForm classes using fields = '__all__' which exposes all model fields
      2. form.save(commit=False) without a subsequent .save() call, indicating
         potential for injecting additional fields
      3. DRF serializers used without proper validation checks
      
      The pattern focuses on the most common and dangerous mass assignment
      patterns in Django applications. It may not catch:
      - Custom form handling logic
      - Dynamic field generation
      - Model.objects.create/update with filtered but still dangerous fields
      - Subtle mass assignment through related models
      
      False positives may occur if fields = '__all__' is used on models with
      only safe fields, though this is still considered bad practice.
      """,
      
      safe_alternatives: [
        """
        # Explicit field whitelisting in ModelForm
        class UserProfileForm(forms.ModelForm):
            class Meta:
                model = UserProfile
                fields = ['first_name', 'last_name', 'bio', 'website']
                # Never use fields = '__all__'
                # Consider using exclude for a few fields, but prefer explicit fields
        
        def update_profile(request):
            form = UserProfileForm(request.POST, instance=request.user.profile)
            if form.is_valid():
                form.save()  # Only whitelisted fields are saved
                return redirect('profile')
        """,
        """
        # DRF Serializer with proper field control
        class UserSerializer(serializers.ModelSerializer):
            class Meta:
                model = User
                fields = ['id', 'username', 'email', 'first_name', 'last_name']
                read_only_fields = ['id', 'username']  # Prevent modification
                extra_kwargs = {
                    'email': {'required': True, 'validators': [validate_email]},
                }
        
        class UserViewSet(viewsets.ModelViewSet):
            serializer_class = UserSerializer
            
            def perform_create(self, serializer):
                # Additional validation and field control
                if serializer.is_valid():
                    serializer.save(created_by=self.request.user)
        """,
        """
        # Safe form.save(commit=False) usage
        def create_article(request):
            form = ArticleForm(request.POST)
            if form.is_valid():
                article = form.save(commit=False)
                # Only set specific, validated fields
                article.author = request.user
                article.published_date = timezone.now()
                article.save()  # Always call save() after modifications
                return redirect('article_detail', pk=article.pk)
        """,
        """
        # Manual field filtering for dynamic scenarios
        ALLOWED_USER_FIELDS = ['first_name', 'last_name', 'bio', 'website']
        
        def update_user_api(request):
            user = request.user
            
            # Filter request data to allowed fields only
            update_data = {
                field: value 
                for field, value in request.POST.items() 
                if field in ALLOWED_USER_FIELDS
            }
            
            # Update only allowed fields
            for field, value in update_data.items():
                setattr(user, field, value)
            
            user.full_clean()  # Validate before saving
            user.save(update_fields=ALLOWED_USER_FIELDS)
        """,
        """
        # Using forms.Form for complete control
        class ProfileUpdateForm(forms.Form):
            first_name = forms.CharField(max_length=30, required=False)
            last_name = forms.CharField(max_length=30, required=False)
            bio = forms.CharField(widget=forms.Textarea, required=False)
            
            def save(self, user):
                # Manually update only form fields
                user.first_name = self.cleaned_data['first_name']
                user.last_name = self.cleaned_data['last_name']
                user.profile.bio = self.cleaned_data['bio']
                user.save()
                user.profile.save()
        """
      ],
      
      additional_context: %{
        common_mistakes: [
          "Using fields = '__all__' for convenience during development",
          "Assuming exclude is safer than explicit fields (it's not)",
          "Forgetting that JSONField can contain arbitrary nested data",
          "Not validating field names in dynamic update scenarios",
          "Trusting form.cleaned_data without field restrictions",
          "Using Model.objects.create(**request.POST.dict())",
          "Not understanding that model validation != mass assignment protection",
          "Assuming authentication prevents mass assignment attacks"
        ],
        
        secure_patterns: [
          """
          # Role-based field access control
          class UserForm(forms.ModelForm):
              class Meta:
                  model = User
                  fields = ['username', 'email', 'first_name', 'last_name']
          
          class AdminUserForm(forms.ModelForm):
              class Meta:
                  model = User
                  fields = ['username', 'email', 'first_name', 'last_name', 
                           'is_staff', 'is_active', 'groups']
          
          def edit_user(request, user_id):
              user = get_object_or_404(User, pk=user_id)
              
              # Use different forms based on permissions
              if request.user.is_superuser:
                  form_class = AdminUserForm
              else:
                  form_class = UserForm
                  
              form = form_class(request.POST or None, instance=user)
              if form.is_valid():
                  form.save()
          """,
          """
          # Audit trail for sensitive field changes
          from django.contrib.admin.models import LogEntry, CHANGE
          
          def update_user_with_audit(request, user_id):
              user = get_object_or_404(User, pk=user_id)
              old_values = {
                  'is_staff': user.is_staff,
                  'is_superuser': user.is_superuser,
              }
              
              form = UserForm(request.POST, instance=user)
              if form.is_valid():
                  user = form.save()
                  
                  # Log any privilege changes
                  for field, old_value in old_values.items():
                      new_value = getattr(user, field)
                      if old_value != new_value:
                          LogEntry.objects.log_action(
                              user_id=request.user.pk,
                              content_type_id=ContentType.objects.get_for_model(user).pk,
                              object_id=user.pk,
                              object_repr=str(user),
                              action_flag=CHANGE,
                              change_message=f"{field} changed from {old_value} to {new_value}"
                          )
          """,
          """
          # Custom model save() for additional protection
          class User(AbstractUser):
              def save(self, *args, **kwargs):
                  # Prevent mass assignment of critical fields
                  if self.pk:  # Existing user
                      old_user = User.objects.get(pk=self.pk)
                      if not hasattr(self, '_privileged_update'):
                          # Restore protected fields
                          self.is_staff = old_user.is_staff
                          self.is_superuser = old_user.is_superuser
                          self.groups = old_user.groups
                  
                  super().save(*args, **kwargs)
              
              def set_privileged_fields(self, **kwargs):
                  # Controlled method for updating protected fields
                  self._privileged_update = True
                  for field, value in kwargs.items():
                      if field in ['is_staff', 'is_superuser']:
                          setattr(self, field, value)
                  self.save()
          """
        ],
        
        framework_specific_notes: [
          "Django ModelForm respects model field validators but not mass assignment",
          "fields = '__all__' was added for convenience but should rarely be used",
          "exclude is not recommended - explicit fields is always better",
          "DRF has separate concepts: fields (serialization) vs read_only_fields",
          "form.save(commit=False) is useful but requires careful handling",
          "Model.clean() is not called by default on save() - use full_clean()",
          "Django admin uses proper field restrictions by default",
          "Consider using Django Guardian for object-level permissions"
        ]
      }
    }
  end
  
  @impl true
  def ast_enhancement do
    %{
      min_confidence: 0.7,
      
      context_rules: %{
        form_attributes: [
          "__all__",
          "fields",
          "exclude",
          "Meta"
        ],
        
        dangerous_methods: [
          "save",
          "create",
          "update",
          "update_or_create",
          "get_or_create"
        ],
        
        serializer_patterns: [
          "data=request",
          "ModelSerializer",
          "Serializer",
          "is_valid()",
          "validated_data"
        ],
        
        safe_patterns: [
          "fields = [",
          "read_only_fields",
          "if form.is_valid():",
          "if serializer.is_valid():"
        ],
        
        request_sources: [
          "request.POST",
          "request.data",
          "request.GET",
          "request.FILES"
        ]
      },
      
      confidence_rules: %{
        adjustments: %{
          # High confidence patterns
          fields_all: +0.95,
          missing_field_list: +0.85,
          direct_create_with_kwargs: +0.9,
          
          # Medium confidence
          save_commit_false: +0.7,
          serializer_without_validation: +0.75,
          exclude_usage: +0.6,
          
          # Lower confidence
          in_test_file: -0.95,
          in_migration: -0.98,
          in_example_docs: -0.9,
          
          # Mitigating factors
          has_field_restrictions: -0.8,
          explicit_field_list: -0.85,
          has_permission_checks: -0.6,
          in_admin_class: -0.7,
          has_validation: -0.75
        }
      },
      
      ast_rules: %{
        form_analysis: %{
          check_fields_attribute: true,
          detect_exclude_usage: true,
          analyze_save_patterns: true,
          check_meta_class: true,
          detect_all_fields: true
        },
        
        serializer_analysis: %{
          check_field_definitions: true,
          detect_validation_calls: true,
          analyze_save_patterns: true,
          check_read_only_fields: true
        },
        
        model_analysis: %{
          detect_direct_creation: true,
          check_kwargs_usage: true,
          analyze_update_patterns: true,
          detect_setattr_usage: true
        },
        
        security_analysis: %{
          check_permission_decorators: true,
          analyze_user_context: true,
          detect_privileged_fields: true,
          check_audit_logging: true
        }
      }
    }
  end
end