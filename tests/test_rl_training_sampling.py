import pytest
import tempfile
import csv
import numpy as np
from pathlib import Path
from unittest.mock import MagicMock, patch

from research.train_rl import load_and_organize_data


class TestRLTrainingSampling:
    @pytest.fixture
    def sample_training_data(self):
        csv_content = [
            ["tokens", "hash", "language", "filepath", "label", "package"],
            [
                "MAL_CODE_1A",
                "hash1a",
                "python",
                "/pkg1/file1.py",
                "malicious",
                "malware_pkg_1",
            ],
            [
                "MAL_CODE_1B",
                "hash1b",
                "python",
                "/pkg1/file2.py",
                "malicious",
                "malware_pkg_1",
            ],
            [
                "MAL_CODE_1C",
                "hash1c",
                "python",
                "/pkg1/file3.py",
                "malicious",
                "malware_pkg_1",
            ],
            [
                "MAL_CODE_2A",
                "hash2a",
                "python",
                "/pkg2/file1.py",
                "malicious",
                "malware_pkg_2",
            ],
            [
                "MAL_CODE_2B",
                "hash2b",
                "python",
                "/pkg2/file2.py",
                "malicious",
                "malware_pkg_2",
            ],
            [
                "MAL_CODE_3A",
                "hash3a",
                "python",
                "/pkg3/file1.py",
                "malicious",
                "malware_pkg_3",
            ],
            ["BENIGN_1", "hashb1", "python", "/benign1.py", "benign", ""],
            ["BENIGN_2", "hashb2", "python", "/benign2.py", "benign", ""],
            ["BENIGN_3", "hashb3", "python", "/benign3.py", "benign", ""],
            ["BENIGN_4", "hashb4", "python", "/benign4.py", "benign", ""],
            ["BENIGN_5", "hashb5", "python", "/benign5.py", "benign", ""],
            ["BENIGN_6", "hashb6", "python", "/benign6.py", "benign", ""],
            ["BENIGN_7", "hashb7", "python", "/benign7.py", "benign", ""],
            ["BENIGN_8", "hashb8", "python", "/benign8.py", "benign", ""],
            ["BENIGN_9", "hashb9", "python", "/benign9.py", "benign", ""],
            ["BENIGN_10", "hashb10", "python", "/benign10.py", "benign", ""],
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, newline=""
        ) as f:
            writer = csv.writer(f)
            writer.writerows(csv_content)
            temp_file_path = f.name

        yield temp_file_path

        Path(temp_file_path).unlink()

    def test_package_grouping_for_training(self, sample_training_data):
        malicious_packages, benign_samples, benign_labels, _, _, _ = load_and_organize_data(
            sample_training_data
        )

        assert len(malicious_packages) == 3

        assert len(malicious_packages["malware_pkg_1"]) == 3
        assert len(malicious_packages["malware_pkg_2"]) == 2
        assert len(malicious_packages["malware_pkg_3"]) == 1

    def test_all_malicious_files_in_same_package_together(self, sample_training_data):
        malicious_packages, _, _, _, _, _ = load_and_organize_data(sample_training_data)

        pkg1_files = malicious_packages["malware_pkg_1"]
        assert "MAL_CODE_1A" in pkg1_files
        assert "MAL_CODE_1B" in pkg1_files
        assert "MAL_CODE_1C" in pkg1_files

        pkg2_files = malicious_packages["malware_pkg_2"]
        assert "MAL_CODE_2A" in pkg2_files
        assert "MAL_CODE_2B" in pkg2_files

    def test_benign_samples_available_for_random_selection(self, sample_training_data):
        _, benign_samples, benign_labels, _, _, _ = load_and_organize_data(sample_training_data)

        assert len(benign_samples) == 10

        expected_samples = [f"BENIGN_{i}" for i in range(1, 11)]
        for expected in expected_samples:
            assert expected in benign_samples

    def test_varying_benign_sample_count_simulation(self, sample_training_data):
        _, benign_samples, _, _, _, _ = load_and_organize_data(sample_training_data)

        rng = np.random.RandomState(42)

        min_samples = 2
        max_samples = 5

        sample_counts = []
        for _ in range(100):
            n_benign = rng.randint(min_samples, max_samples + 1)
            sample_counts.append(n_benign)

        assert min(sample_counts) >= min_samples
        assert max(sample_counts) <= max_samples

        unique_counts = set(sample_counts)
        assert len(unique_counts) > 1

    def test_random_benign_sampling_without_replacement(self, sample_training_data):
        _, benign_samples, _, _, _, _ = load_and_organize_data(sample_training_data)

        rng = np.random.RandomState(42)
        n_benign = 5
        selected_indices = rng.choice(len(benign_samples), size=n_benign, replace=False)

        assert len(selected_indices) == n_benign
        assert len(set(selected_indices)) == n_benign

        selected_samples = [benign_samples[i] for i in selected_indices]
        assert len(selected_samples) == n_benign

    def test_benign_sampling_handles_edge_cases(self, sample_training_data):
        _, benign_samples, _, _, _, _ = load_and_organize_data(sample_training_data)

        rng = np.random.RandomState(42)

        n_benign = len(benign_samples) + 5
        selected_indices = rng.choice(
            len(benign_samples), size=min(n_benign, len(benign_samples)), replace=False
        )

        assert len(selected_indices) == len(benign_samples)

    def test_epoch_based_package_shuffling(self, sample_training_data):
        malicious_packages, _, _, _, _, _ = load_and_organize_data(sample_training_data)

        package_names = list(malicious_packages.keys())

        rng = np.random.RandomState(42)

        shuffled_epoch_1 = rng.permutation(package_names).tolist()
        rng = np.random.RandomState(42)
        shuffled_epoch_2 = rng.permutation(package_names).tolist()

        assert shuffled_epoch_1 == shuffled_epoch_2

        rng = np.random.RandomState(42)
        shuffled_a = rng.permutation(package_names).tolist()
        rng = np.random.RandomState(123)
        shuffled_b = rng.permutation(package_names).tolist()

        assert set(shuffled_a) == set(package_names)
        assert set(shuffled_b) == set(package_names)

    def test_training_loop_structure_simulation(self, sample_training_data):
        malicious_packages, benign_samples, _, _, _, _ = load_and_organize_data(
            sample_training_data
        )

        package_names = list(malicious_packages.keys())
        rng = np.random.RandomState(42)

        epochs = 2
        min_benign = 1
        max_benign = 3

        total_malicious_episodes = 0
        total_benign_episodes = 0

        for epoch in range(epochs):
            shuffled_packages = rng.permutation(package_names).tolist()

            for package_name in shuffled_packages:
                package_files = malicious_packages[package_name]

                for file_tokens in package_files:
                    total_malicious_episodes += 1

                n_benign = rng.randint(min_benign, max_benign + 1)
                selected_benign_indices = rng.choice(
                    len(benign_samples),
                    size=min(n_benign, len(benign_samples)),
                    replace=False,
                )

                for _ in selected_benign_indices:
                    total_benign_episodes += 1

        expected_malicious_per_epoch = sum(
            len(files) for files in malicious_packages.values()
        )
        expected_total_malicious = expected_malicious_per_epoch * epochs

        assert total_malicious_episodes == expected_total_malicious

        assert total_benign_episodes > 0

    def test_package_processing_order_varies_across_epochs(self, sample_training_data):
        malicious_packages, _, _, _, _, _ = load_and_organize_data(sample_training_data)

        package_names = list(malicious_packages.keys())

        epoch_orders = []
        for seed in range(5):
            rng = np.random.RandomState(seed)
            shuffled = rng.permutation(package_names).tolist()
            epoch_orders.append(tuple(shuffled))

        unique_orders = set(epoch_orders)
        assert len(unique_orders) > 1

    def test_labels_consistency(self, sample_training_data):
        malicious_packages, benign_samples, benign_labels, _, _, _ = load_and_organize_data(
            sample_training_data
        )

        assert len(benign_samples) == len(benign_labels)

        assert all(label == 0 for label in benign_labels)

        for package_name, files in malicious_packages.items():
            assert len(files) > 0
            for file_tokens in files:
                assert isinstance(file_tokens, str)
                assert len(file_tokens) > 0
