from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Notification
from utils.helpers import send_push_to_user  # adjust path if needed

@receiver(post_save, sender=Notification)
def send_push_notification_on_create(sender, instance, created, **kwargs):
    if created:
        print("notification signal >>>>>>>>>>>>>>>>>>>>>>>>")
        send_push_to_user(
            user=instance.user,
            title="A New Notification",
            body=instance.message,
            data={}
        )
