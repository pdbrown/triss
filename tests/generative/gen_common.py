# Copyright: (c) 2024, Philip Brown
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from hypothesis import settings, strategies as st


# Increase default deadline from 200ms -> 5000ms.
# The deadline applies to a single example. A test will fail if examples
# consistently take longer than the deadline.
settings.register_profile("default", deadline=5000)
settings.load_profile("default")


@st.composite
def m_and_n(draw, n=st.integers(min_value=2, max_value=10)):
    n = draw(n)
    m = draw(st.integers(min_value=2, max_value=n))
    return (m, n)
