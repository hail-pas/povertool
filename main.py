import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'povertool.settings')

if __name__ == '__main__':
    """Run administrative tasks."""

    try:
        from django.core.management import execute_from_command_line, ManagementUtility
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    utility = ManagementUtility(["manage,py", "runserver", "8000"])
    utility.execute()
