from django.contrib import admin
from django import forms
from django.contrib.auth.hashers import make_password
from .models import Team, Quiz, Question, Score, HintRequest, TeamQuestion, Answer, TeamUser , Hint, SiteSettings, UserPerson

# Custom form for UserPerson to handle password securely
class UserPersonForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, required=False)

    class Meta:
        model = UserPerson
        fields = '__all__'

    def save(self, commit=True):
        user_person = super().save(commit=False)
        if self.cleaned_data['password']:
            user_person.set_password(self.cleaned_data['password'])
        if commit:
            user_person.save()
        return user_person

# Admin configuration for the Team model
class TeamAdmin(admin.ModelAdmin):
    list_display = ('id', 'name')
    search_fields = ('name',)
    fields = ('name', 'user')  # Assuming you want to display the user associated with the team

# Admin configuration for the Quiz model
class QuizAdmin(admin.ModelAdmin):
    list_display = ('id', 'is_active')
    list_filter = ('is_active',)

# Admin configuration for the Question model
class QuestionAdmin(admin.ModelAdmin):
    list_display = ('id', 'question_type', 'question_text', 'common_question', 'active')
    list_filter = ('common_question', 'active', 'question_type')
    search_fields = ('question_text', 'correct_answer')

# Admin configuration for the TeamQuestion model
class TeamQuestionAdmin(admin.ModelAdmin):
    list_display = ('id', 'team', 'question', 'hint_used', 'answered')
    list_filter = ('team', 'answered')
    raw_id_fields = ('team', 'question')

# Admin configuration for the Score model
class ScoreAdmin(admin.ModelAdmin):
    list_display = ('id', 'team', 'score')
    list_filter = ('team',)

# Admin configuration for the Answer model
class AnswerAdmin(admin.ModelAdmin):
    list_display = ('team', 'question', 'submitted_answer', 'score', 'is_correct')
    search_fields = ('team__name', 'question__question_text')

# Admin configuration for the UserPerson model
class UserPersonAdmin(admin.ModelAdmin):
    form = UserPersonForm
    list_display = ('name', 'email', 'class_id', 'department', 'wp_number')
    search_fields = ('name', 'email', 'class_id')
    list_filter = ('department',)
    ordering = ('name',)

    fieldsets = (
        (None, {
            'fields': ('name', 'email', 'password')
        }),
        ('Personal Info', {
            'fields': ('class_id', 'department', 'wp_number')
        }),
        ('Additional Info', {
            'fields': ('nullable_text_field',),
            'classes': ('collapse',)
        })
    )

# Admin configuration for the Hint model
class HintAdmin(admin.ModelAdmin):
    list_display = ('id', 'question', 'hint_text')
    search_fields = ('hint_text',)

# Admin configuration for the HintRequest model
class HintRequestAdmin(admin.ModelAdmin):
    list_display = ('id', 'team', 'question', 'requested_at', 'is_fulfilled')
    list_filter = ('is_fulfilled', 'team', 'question')

# Admin configuration for the SiteSettings model
class SiteSettingsAdmin(admin.ModelAdmin):
    list_display = ('registration_open', 'login_open')

# Register the models with the admin site
admin.site.register(Team, TeamAdmin)
admin.site.register(TeamUser)
admin.site.register(Quiz, QuizAdmin)
admin.site.register(Question, QuestionAdmin)
admin.site.register(Score, ScoreAdmin)
admin.site.register(TeamQuestion, TeamQuestionAdmin)
admin.site.register(Answer, AnswerAdmin)
admin.site.register(UserPerson, UserPersonAdmin)
admin.site.register(Hint, HintAdmin)
admin.site.register(HintRequest, HintRequestAdmin)
admin.site.register(SiteSettings, SiteSettingsAdmin)