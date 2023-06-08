from django.utils import timezone

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

"""
class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('L\'adresse e-mail est obligatoire')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser):
    email = models.EmailField(unique=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'

    def __str__(self):
        return f"{self.email}"
"""
SEXE_CHOICES = (

    ("HOMME", "HOMME"),
    ("FEMME", "FEMME"),
    ("NON_DEFINI","NON_DEFINI")


)

class MyUserManager(BaseUserManager):
    def create_user(self, email, lastname, firstname, password=None, birth_date=timezone.now(), sexe='', adresse='', description='', profession='', telephone=''):
        """
        Creates and saves a User with the given email, name and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        user = self.model(
            email=self.normalize_email(email),
            lastname=lastname,
            firstname=firstname,
            birth_date=birth_date,
            adresse=adresse,
            description=description,
            profession=profession,
            telephone=telephone,
            sexe=sexe

        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, lastname, firstname, password=None, birth_date=timezone.now(), sexe='', adresse='', description='', profession='', telephone=''):
        """
        Creates and saves a superuser with the given email, name and password.
        """
        user = self.create_user(
            email,
            password=password,
            lastname=lastname,
            firstname=firstname,
            birth_date=birth_date,
            sexe=sexe,
            adresse=adresse,
            description=description,
            profession=profession,
            telephone=telephone

        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
    )

    lastname = models.CharField(max_length=200)
    firstname = models.CharField(max_length=200)
    sexe = models.CharField(max_length=15, choices=SEXE_CHOICES,default="NON_DEFINI")
    picture = models.ImageField(default="default.png")
    telephone = models.CharField(max_length=20, default="")
    birth_date = models.DateField(default=timezone.now)
    adresse=models.CharField(max_length=200, default="")
    description = models.CharField(max_length=200, default="Aucune description")
    profession = models.CharField(max_length=200, default="Aucune rofession")
    is_admin = models.BooleanField(default=False)


    date_created_at = models.DateTimeField(auto_now_add=True)
    date_updated_at = models.DateTimeField(auto_now=True)

    objects = MyUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['lastname', 'firstname']

    def __str__(self):
        return f"{self.lastname} {self.firstname}"

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin


