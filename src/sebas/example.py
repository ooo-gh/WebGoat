from django.db import connection
from django.db import connections
from django.db import models
from django.db.models.expressions import RawSQL
from rest_framework.decorators import api_view

class Question(models.Model):
    question_text = models.CharField(max_length=200)
    pub_date = models.DateTimeField("date published")

@api_view(["GET", "POST"])
def snippet_list(request):
  name = request.GET.get('name', 'wazzzup?')
  # ruleid: djangoorm-django
  q = Question.objects.raw(f"SELECT * FROM question WHERE text = '{name}'")

  # ruleid: djangoorm-django
  q = Question.objects.extra({"val": f"SELECT * FROM question WHERE text = '{name}'"}).all()

  # ok: djangoorm-django
  q = Question.objects.raw(f"SELECT * FROM question WHERE text = '%s'", [name])

@api_view(["GET", "POST"])
def example_test(request):
  name = request.GET.get('name', 'wazzzup?')

  with connection.cursor() as cursor:
    # proruleid: djangoorm-django
    cursor.execute(f"SELECT * FROM question WHERE text = '{name}'")
