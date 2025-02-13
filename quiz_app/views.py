from pyexpat.errors import messages

from aiohttp_session import Session
from bottle import Response
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseRedirect, HttpResponse
from django.db.models import Sum
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_http_methods
import json
import logging

from docutils.nodes import status
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from quiz_app.forms import RegistrationForm
from quiz_app.models import UserPerson, SiteSettings, Answer, HintRequest, Team, Question, Quiz, TeamUser, \
    HintNotification, Hint
from quiz_app.serializers import LoginSerializer, HintNotificationSerializer, HintSerializer, TeamUserSerializer, \
    AnswerSerializer, HintRequestSerializer, QuestionSerializer, QuizSerializer, TeamSerializer

logger = logging.getLogger(__name__)


def reg_error(request):
    return render(request, 'reg.html')





def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            # Assuming the user is associated with a team
            team = Team.objects.get(user=user)
            request.session['team_id'] = team.id  # Set team_id in session
            return redirect('team_profile')
    return render(request, 'login.html')
@login_required
def team_profile(request):
    team = Team.objects.get(user=request.user)
    quiz = Quiz.objects.first()
    team_users = TeamUser.objects.filter(team=team)

    return render(request, 'team_profile.html', {
        'team': team,
        'quiz': quiz,
        'team_users': team_users  # Pass the team users to the template
    })


@login_required
def quiz_view(request):
    team_id = request.session.get('team_id')
    if not team_id:
        return HttpResponseRedirect(reverse('team_profile'))  # Redirect if team_id is not set

    try:
        team = Team.objects.get(id=team_id)
    except Team.DoesNotExist:
        # Handle the case where the team does not exist
        return HttpResponseRedirect(reverse('team_profile'))  # Redirect to profile or another page

    quiz = Quiz.objects.first()

    if not quiz.is_active:
        return HttpResponseRedirect(reverse('team_profile'))

    common_questions = list(Question.objects.filter(quiz=quiz, common_question=True))
    unique_questions = list(Question.objects.filter(teamquestion__team=team, common_question=False))
    submitted_answers = list(Answer.objects.filter(team=team).select_related('question'))

    answered_questions = {
        answer.question.id: answer.question.correct_answer for answer in submitted_answers
    }

    return render(request, 'quiz.html', {
        'common_questions': common_questions,
        'unique_questions': unique_questions,
        'answered_questions': answered_questions or {},
        'team': team
    })


@csrf_exempt
@require_POST
def submit_answer(request, question_id):
    try:
        data = json.loads(request.body)
        answer_text = data.get('answer')

        if not answer_text:
            return JsonResponse(
                {'success': False, 'error': 'Answer cannot be empty.'},
                status=400
            )

        question = get_object_or_404(Question, id=question_id)
        is_correct = (answer_text.strip().lower() == question.correct_answer.strip().lower())

        if is_correct:
            team = Team.objects.get(id=request.session.get('team_id'))
            Answer.objects.create(
                team=team,
                question=question,
                submitted_answer=answer_text,
                is_correct=True,
                score=10 if question.common_question else 20
            )

        return JsonResponse({
            'success': True,
            'is_correct': is_correct,
        })

    except Exception as e:
        return JsonResponse(
            {'success': False, 'error': str(e)},
            status=500
        )
@login_required
def request_hint(request):
    if request.method == 'POST':
        question_id = request.POST.get('question_id')
        team_id = request.session.get('team_id')

        try:
            team = Team.objects.get(id=team_id)
            question = Question.objects.get(id=question_id)
            HintRequest.objects.create(team=team, question=question)
            return redirect('hint_requests')
        except (Team.DoesNotExist, Question.DoesNotExist):
            return JsonResponse({'success': False, 'error': 'Team or Question not found.'})

    team_id = request.session.get('team_id')
    user_team = Team.objects.get(id=team_id)
    questions = list(Question.objects.all())

    return render(request, 'request_hint.html', {
        'questions': questions,
        'user_team': user_team
    })


@login_required
def hint_requests(request):
    team_id = request.session.get('team_id')
    hint_requests = list(HintRequest.objects.filter(team_id=team_id))
    return render(request, 'hint_requests.html', {'hint_requests': hint_requests})


def scoreboard(request):
    teams = Team.objects.all()
    scoreboard_data = []

    for team in teams:
        total_score = Answer.objects.filter(team=team).aggregate(total=Sum('score'))['total'] or 0
        hint_requests = HintRequest.objects.filter(team=team).count()
        approved_requests = HintRequest.objects.filter(team=team, is_fulfilled=True).count()
        answered_questions = Answer.objects.filter(team=team, is_correct=True).count()

        score_after_deduction = total_score - (approved_requests * 5)
        scoreboard_data.append({
            'team_name': team.name,
            'score': max(score_after_deduction, 0),
            'hint_requests': hint_requests,
            'approved_requests': approved_requests,
            'solved_questions': answered_questions,
        })

    scoreboard_data.sort(key=lambda x: (-x['score'], x['approved_requests']))
    return render(request, 'scoreboard.html', {'scoreboard_data': scoreboard_data})


def custom_404_view(request, exception):
    return render(request, '404.html', status=404)


def custom_500_view(request):
    return render(request, '404.html', status=500)


@require_http_methods(["GET"])
def home(request):
    settings = get_site_settings()
    return render(request, 'home1.html', {
        'registration_open': settings.registration_open,
        'login_open': settings.login_open
    })


def get_site_settings():
    try:
        return SiteSettings.objects.first()
    except SiteSettings.DoesNotExist:
        return SiteSettings.objects.create(
            registration_open=True,
            login_open=True
        )


@require_http_methods(["GET", "POST"])
def register(request):
    settings = SiteSettings.objects.first()
    if not settings or not settings.registration_open:
        return render(request, 'registration_closed.html', {})

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            return redirect('done')
    else:
        form = RegistrationForm()

    return render(request, 'register.html', {'form': form})


def user_login_view(request):
    error_message = None

    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        logger.info(f"Attempting login for email: {email}")

        try:
            user = UserPerson.objects.get(email=email)
            logger.info(f"User found: {user.email}")

            if user.check_password(password):
                request.session['email'] = user.email
                request.session.save()
                logger.info("Login successful, redirecting to profile")
                return redirect('user_profile')
            else:
                logger.warning("Invalid password")
                error_message = "Invalid email or password"
        except UserPerson.DoesNotExist:
            logger.warning("User not found")
            error_message = "Invalid email or password"

    return render(request, 'user_login.html', {'error_message': error_message})


def user_profile(request):
    email = request.session.get('email')
    if not email:
        logger.warning("No email in session, redirecting to login")
        return redirect('user_login')

    try:
        user = UserPerson.objects.get(email=email)
        logger.info(f"Rendering profile for user: {user.email}")
        return render(request, 'profile.html', {'user': user})
    except UserPerson.DoesNotExist:
        logger.warning("User not found")
        return redirect('user_login')


def done(request):
    return render(request, 'done.html')
# REST APIs
class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            team_name = serializer.validated_data['username']  # Assuming username is the team name
            password = serializer.validated_data['password']

            try:
                team = Team.objects.get(name=team_name)
                if team.check_password(password):
                    request.session['team_id'] = team.id  # Store team ID in session
                    return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
                else:
                    return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
            except Team.DoesNotExist:
                return Response({"error": "Team not found"}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TeamViewSet(viewsets.ModelViewSet):
    queryset = Team.objects.all()
    serializer_class = TeamSerializer
    permission_classes = [IsAuthenticated]


class QuizViewSet(viewsets.ModelViewSet):
    queryset = Quiz.objects.all()
    serializer_class = QuizSerializer
    permission_classes = [IsAuthenticated]


class QuestionViewSet(viewsets.ModelViewSet):
    queryset = Question.objects.all()
    serializer_class = QuestionSerializer
    permission_classes = [IsAuthenticated]


class HintRequestViewSet(viewsets.ModelViewSet):
    queryset = HintRequest.objects.all()
    serializer_class = HintRequestSerializer
    permission_classes = [IsAuthenticated]


class AnswerViewSet(viewsets.ModelViewSet):
    queryset = Answer.objects.all()
    serializer_class = AnswerSerializer
    permission_classes = [IsAuthenticated]


class TeamUserViewSet(viewsets.ModelViewSet):
    queryset = TeamUser.objects.all()
    serializer_class = TeamUserSerializer
    permission_classes = [IsAuthenticated]


class HintViewSet(viewsets.ModelViewSet):
    queryset = Hint.objects.all()
    serializer_class = HintSerializer
    permission_classes = [IsAuthenticated]


class HintNotificationViewSet(viewsets.ModelViewSet):
    queryset = HintNotification.objects.all()
    serializer_class = HintNotificationSerializer
    permission_classes = [IsAuthenticated]


class SubmitAnswerAPI(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, question_id):
        try:
            answer_text = request.data.get('answer')
            if not answer_text:
                return Response(
                    {'success': False, 'error': 'Answer cannot be empty.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            question = get_object_or_404(Question, id=question_id)
            is_correct = (answer_text.strip().lower() == question.correct_answer.strip().lower())

            if is_correct:
                team = Team.objects.get(user=request.user)
                Answer.objects.create(
                    team=team,
                    question=question,
                    submitted_answer=answer_text,
                    is_correct=True,
                    score=10 if question.common_question else 20
                )

            return Response({
                'success': True,
                'is_correct': is_correct,
            })

        except Exception as e:
            return Response(
                {'success': False, 'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScoreboardAPI(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        teams = Team.objects.all()
        scoreboard_data = []

        for team in teams:
            total_score = Answer.objects.filter(team=team).aggregate(total=Sum('score'))['total'] or 0
            hint_requests = HintRequest.objects.filter(team=team).count()
            approved_requests = HintRequest.objects.filter(team=team, is_fulfilled=True).count()
            answered_questions = Answer.objects.filter(team=team, is_correct=True).count()

            score_after_deduction = total_score - (approved_requests * 5)
            scoreboard_data.append({
                'team_name': team.name,
                'score': max(score_after_deduction, 0),
                'hint_requests': hint_requests,
                'approved_requests': approved_requests,
                'solved_questions': answered_questions,
            })

        scoreboard_data.sort(key=lambda x: (-x['score'], x['approved_requests']))
        return Response(scoreboard_data)