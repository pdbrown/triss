from hypothesis import settings


# Increase default deadline from 200ms -> 1000ms.
# The deadline applies to a single example. A test will fail if examples
# consistently take longer than the deadline.
settings.register_profile("default", deadline=5000)
settings.load_profile("default")
