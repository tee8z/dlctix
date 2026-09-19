use bitcoin::{transaction::InputWeightPrediction, Amount, FeeRate};

use std::collections::BTreeMap;

use crate::errors::Error;

/// Compute the fee for a transaction given a fixed [`FeeRate`], input weights,
/// and output script lengths.
pub(crate) fn fee_calc_safe<I, O>(
    fee_rate: FeeRate,
    input_weights: I,
    output_spk_lens: O,
) -> Result<Amount, Error>
where
    I: IntoIterator<Item = InputWeightPrediction>,
    O: IntoIterator<Item = usize>,
{
    let tx_weight = bitcoin::transaction::predict_weight(input_weights, output_spk_lens);
    let fee = fee_rate.fee_wu(tx_weight).ok_or(Error::WeightOverflow)?;
    Ok(fee)
}

/// Safely compute the given output amount by subtracting the fee
/// amount from the amount of available coins. Returns an error if
/// the result is negative, or is less than the given dust threshold.
pub(crate) fn fee_subtract_safe(
    available_coins: Amount,
    fee: Amount,
    dust_threshold: Amount,
) -> Result<Amount, Error> {
    if fee >= available_coins {
        return Err(Error::InsufficientFunds);
    }
    let after_fee = available_coins
        .checked_sub(fee)
        .ok_or(Error::InvalidFeeAmount)?;
    if after_fee <= dust_threshold {
        return Err(Error::DustAmount);
    }
    Ok(after_fee)
}

/// Safely compute the output amounts for a set of outputs by computing
/// and distributing the fee equally among all output values.
///
/// Returns an error if any output value is negative, or is less than the
/// given dust threshold.
pub(crate) fn fee_calc_shared<I, O, T>(
    available_coins: Amount,
    fee_rate: FeeRate,
    input_weights: I,
    output_spk_lens: O,
    dust_threshold: Amount,
    payout_map: &BTreeMap<T, u64>,
) -> Result<BTreeMap<T, Amount>, Error>
where
    I: IntoIterator<Item = InputWeightPrediction>,
    O: IntoIterator<Item = usize>,
    T: Copy + Ord,
{
    let fee_total = fee_calc_safe(fee_rate, input_weights, output_spk_lens)?;

    let n_outputs = u64::try_from(payout_map.len()).map_err(|_| Error::PayoutWeightOverflow)?;
    if n_outputs == 0 {
        return Err(Error::EmptyPayoutMap);
    }

    // Mining fees are distributed equally among all winners, regardless of payout weight.
    let fee_shared = fee_total / n_outputs;

    // All arithmetic is checked: the payout map may originate from untrusted
    // parameters, and an overflow must surface as an error rather than a panic
    // or a silently wrong payout.
    let total_weight = payout_map
        .values()
        .try_fold(0u64, |acc, &weight| acc.checked_add(weight))
        .ok_or(Error::PayoutWeightOverflow)?;
    if total_weight == 0 {
        return Err(Error::InvalidPayoutWeight);
    }

    // Payout amounts are computed by using relative weights.
    payout_map
        .iter()
        .map(|(&key, &weight)| {
            let payout = available_coins
                .checked_mul(weight)
                .ok_or(Error::PayoutWeightOverflow)?
                / total_weight;
            let payout_value = fee_subtract_safe(payout, fee_shared, dust_threshold)?;
            Ok((key, payout_value))
        })
        .collect()
}
