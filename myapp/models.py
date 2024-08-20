from django.db import models

class Students(models.Model):
    name = models.CharField(max_length=128)
    age = models.IntegerField()
    address = models.CharField(max_length=256)
    username = models.CharField(max_length=25)
    password = models.CharField(max_length=25)

    @property
    def is_authenticated(self):
        # Trả về True vì đây chỉ là một thuộc tính giả định
        return True

    def __str__(self):
        return f"{self.name} - {self.age} Years Old"
