import random
import pandas as pd
from datetime import datetime, timedelta

random.seed(42)  # reproducibility, same reason as the sampling script

NUM_USERS = 500
COUNTRIES = ["IN", "US", "GB", "DE", "SG", "AU", "BR", "NG"]

ROLE_ACTIONS = {
    "viewer": ["GetObject", "ListBuckets", "DescribeInstances", "ListUsers"],
    "analyst": ["GetObject", "ListBuckets", "DescribeInstances", "ListUsers",
                "PutObject", "CreateSnapshot", "DescribeSnapshots"],
    "admin": ["GetObject", "ListBuckets", "DescribeInstances", "ListUsers",
              "PutObject", "CreateSnapshot", "DescribeSnapshots",
              "DeleteUser", "ModifyIAMPolicy", "CreateAccessKey", "DeleteBucket"],
}

PRIVILEGED_ACTIONS = {"DeleteUser", "ModifyIAMPolicy", "CreateAccessKey", "DeleteBucket"}


def build_user_population(num_users=NUM_USERS):
    users = []
    for i in range(num_users):
        role = random.choices(
            ["viewer", "analyst", "admin"],
            weights=[0.6, 0.3, 0.1],
        )[0]

        users.append({
            "user_id": f"user_{i:04d}",
            "role": role,
            "home_country": random.choice(COUNTRIES),
            "active_start_hour": random.randint(7, 10),   # typical workday start
            "active_end_hour": random.randint(17, 20),    # typical workday end
        })
    return pd.DataFrame(users)


if __name__ == "__main__":
    users_df = build_user_population()
    print(users_df.shape)
    print(users_df["role"].value_counts())
    print(users_df.head(10))
import uuid

NUM_DAYS = 60
START_DATE = datetime(2026, 6, 1)
ACTIVE_DAY_PROBABILITY = 0.7
MIN_EVENTS_PER_SESSION = 3
MAX_EVENTS_PER_SESSION = 15

STATUS_WEIGHTS = {"SUCCESS": 0.95, "FAILURE": 0.05}


def random_ip_for_country(country):
    # Simple placeholder IP generation — not geographically accurate,
    # just needs to be consistent per country for our purposes
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def generate_normal_events(users_df):
    events = []

    for _, user in users_df.iterrows():
        actions_pool = ROLE_ACTIONS[user["role"]]

        for day_offset in range(NUM_DAYS):
            if random.random() > ACTIVE_DAY_PROBABILITY:
                continue  # user not active this day

            current_date = START_DATE + timedelta(days=day_offset)
            num_events = random.randint(MIN_EVENTS_PER_SESSION, MAX_EVENTS_PER_SESSION)

            for _ in range(num_events):
                hour = random.randint(user["active_start_hour"], user["active_end_hour"])
                minute = random.randint(0, 59)
                timestamp = current_date.replace(hour=hour, minute=minute)

                action = random.choice(actions_pool)
                status = random.choices(
                    list(STATUS_WEIGHTS.keys()),
                    weights=list(STATUS_WEIGHTS.values()),
                )[0]

                events.append({
                    "event_id": str(uuid.uuid4()),
                    "timestamp": timestamp,
                    "user_id": user["user_id"],
                    "role": user["role"],
                    "source_ip": random_ip_for_country(user["home_country"]),
                    "country": user["home_country"],
                    "action": action,
                    "status": status,
                    "is_privileged_action": action in PRIVILEGED_ACTIONS,
                    "is_attack": False,       # ground truth, kept separate from model features
                    "attack_type": None,
                })

    return pd.DataFrame(events)


if __name__ == "__main__":
    users_df = build_user_population()
    normal_df = generate_normal_events(users_df)
    print(normal_df.shape)
    print(normal_df["action"].value_counts())
    print(normal_df["is_privileged_action"].value_counts())
    print(normal_df.head()) 
ATTACK_USER_FRACTION = 0.03  # ~3% of users get an attack injected

FOREIGN_COUNTRIES = COUNTRIES  # reuse the same pool for "a country that isn't home"


def inject_brute_force(user, base_date):
    """Many failed logins in a tight window — credential attack pattern."""
    events = []
    hour = random.randint(0, 23)  # attacks don't respect business hours
    for i in range(random.randint(15, 40)):
        timestamp = base_date.replace(hour=hour, minute=0) + timedelta(seconds=i * 10)
        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "user_id": user["user_id"],
            "role": user["role"],
            "source_ip": random_ip_for_country(user["home_country"]),
            "country": user["home_country"],
            "action": "Login",
            "status": "FAILURE",
            "is_privileged_action": False,
            "is_attack": True,
            "attack_type": "brute_force",
        })
    return events


def inject_account_takeover(user, base_date):
    """Login from a country the user has never used, no travel gap."""
    foreign_country = random.choice([c for c in FOREIGN_COUNTRIES if c != user["home_country"]])
    timestamp = base_date.replace(hour=random.randint(0, 23), minute=random.randint(0, 59))
    return [{
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp,
        "user_id": user["user_id"],
        "role": user["role"],
        "source_ip": random_ip_for_country(foreign_country),
        "country": foreign_country,
        "action": "Login",
        "status": "SUCCESS",
        "is_privileged_action": False,
        "is_attack": True,
        "attack_type": "account_takeover",
    }]


def inject_privilege_abuse(user, base_date):
    """A normally low-privilege user performs privileged actions."""
    events = []
    privileged = list(PRIVILEGED_ACTIONS)
    for i in range(random.randint(3, 8)):
        timestamp = base_date.replace(hour=random.randint(0, 23), minute=random.randint(0, 59))
        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "user_id": user["user_id"],
            "role": user["role"],
            "source_ip": random_ip_for_country(user["home_country"]),
            "country": user["home_country"],
            "action": random.choice(privileged),
            "status": "SUCCESS",
            "is_privileged_action": True,
            "is_attack": True,
            "attack_type": "privilege_abuse",
        })
    return events


def inject_reconnaissance(user, base_date):
    """High volume of List/Describe actions in a short window."""
    events = []
    recon_actions = ["ListUsers", "ListBuckets", "DescribeInstances", "DescribeSnapshots"]
    hour = random.randint(0, 23)
    for i in range(random.randint(30, 60)):
        timestamp = base_date.replace(hour=hour, minute=0) + timedelta(seconds=i * 5)
        events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "user_id": user["user_id"],
            "role": user["role"],
            "source_ip": random_ip_for_country(user["home_country"]),
            "country": user["home_country"],
            "action": random.choice(recon_actions),
            "status": "SUCCESS",
            "is_privileged_action": False,
            "is_attack": True,
            "attack_type": "reconnaissance",
        })
    return events


ATTACK_FUNCTIONS = [
    inject_brute_force,
    inject_account_takeover,
    inject_privilege_abuse,
    inject_reconnaissance,
]


def generate_attack_events(users_df):
    events = []
    attack_users = users_df.sample(frac=ATTACK_USER_FRACTION, random_state=42)

    for _, user in attack_users.iterrows():
        attack_func = random.choice(ATTACK_FUNCTIONS)
        attack_day = random.randint(0, NUM_DAYS - 1)
        base_date = START_DATE + timedelta(days=attack_day)
        events.extend(attack_func(user, base_date))

    return pd.DataFrame(events)


def build_full_dataset():
    users_df = build_user_population()
    normal_df = generate_normal_events(users_df)
    attack_df = generate_attack_events(users_df)

    full_df = pd.concat([normal_df, attack_df], ignore_index=True)
    full_df = full_df.sort_values("timestamp").reset_index(drop=True)

    return full_df


if __name__ == "__main__":
    full_df = build_full_dataset()

    print("Total events:", full_df.shape)
    print()
    print("is_attack breakdown:")
    print(full_df["is_attack"].value_counts())
    print()
    print("Attack rate: {:.3f}%".format(
        100 * full_df["is_attack"].sum() / len(full_df)
    ))

    full_df.to_csv("data/raw/synthetic_activity.csv", index=False)
    print("\nSaved to data/raw/synthetic_activity.csv")