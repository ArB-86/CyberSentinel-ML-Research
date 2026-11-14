import numpy as np

from experiments.isolation_forest_ablation import (
    BASELINE_CONFIG,
    CONFIGS,
    TRANSFORMS,
    make_feature_views,
)


def test_ablation_includes_current_raw_default_baseline():
    assert "raw" in TRANSFORMS
    assert BASELINE_CONFIG in CONFIGS


def test_signed_log_transform_preserves_shape_and_sign():
    train = np.array([[-100.0, 0.0], [1.0, 10.0], [3.0, -5.0]])
    validation = np.array([[-2.0, 4.0]])
    test = np.array([[8.0, -9.0]])

    train_view, validation_view, test_view, transformer = make_feature_views(
        "signed_log1p", train, validation, test, seed=7
    )

    assert transformer is None
    assert train_view.shape == train.shape
    assert validation_view.shape == validation.shape
    assert test_view.shape == test.shape
    assert np.sign(train_view).tolist() == np.sign(train).tolist()
    assert np.isfinite(train_view).all()
    assert np.isfinite(validation_view).all()
    assert np.isfinite(test_view).all()


def test_quantile_transform_is_fitted_on_training_data_only():
    train = np.array([[0.0], [1.0], [2.0], [3.0], [4.0]])
    validation = np.array([[100.0], [200.0]])
    test = np.array([[-100.0]])

    train_view, validation_view, test_view, transformer = make_feature_views(
        "quantile_uniform", train, validation, test, seed=11
    )

    assert transformer is not None
    assert float(np.max(transformer.quantiles_)) == 4.0
    assert train_view.shape == train.shape
    assert validation_view.shape == validation.shape
    assert test_view.shape == test.shape
    assert np.isfinite(train_view).all()
    assert np.isfinite(validation_view).all()
    assert np.isfinite(test_view).all()


def test_raw_view_does_not_change_features():
    train = np.array([[0.0, 1.0], [2.0, 3.0]])
    validation = np.array([[4.0, 5.0]])
    test = np.array([[6.0, 7.0]])

    train_view, validation_view, test_view, transformer = make_feature_views(
        "raw", train, validation, test, seed=13
    )

    assert transformer is None
    np.testing.assert_array_equal(train_view, train)
    np.testing.assert_array_equal(validation_view, validation)
    np.testing.assert_array_equal(test_view, test)
