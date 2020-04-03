import { ValidationError } from 'cashaddrjs';
import { isCash, isToken, toLegacy } from '../Ticker';

test('Correctly validates cash address with bitcoincash: prefix', async () => {
    const result = isCash(
        'bitcoincash:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gjykk3wa0',
    );
    expect(result).toStrictEqual(true);
});

test('Correctly validates cash address with ecash: prefix', async () => {
    const result = isCash('ecash:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gtfza25mc');
    expect(result).toStrictEqual(true);
});

test('Correctly validates token address with simpleledger: prefix', async () => {
    const result = isToken(
        'simpleledger:qpmytrdsakt0axrrlswvaj069nat3p9s7c8w5tu8gm',
    );
    expect(result).toStrictEqual(true);
});

test('Correctly validates token address with etoken: prefix (prefix only, not checksum)', async () => {
    const result = isToken('etoken:qpmytrdsakt0axrrlswvaj069nat3p9s7c8w5tu8gm');
    expect(result).toStrictEqual(true);
});

test('Recognizes unaccepted token prefix (prefix only, not checksum)', async () => {
    const result = isToken(
        'wtftoken:qpmytrdsakt0axrrlswvaj069nat3p9s7c8w5tu8gm',
    );
    expect(result).toStrictEqual(false);
});

test('Knows that acceptable cash prefixes are not tokens', async () => {
    const result = isToken('ecash:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gtfza25mc');
    expect(result).toStrictEqual(false);
});

test('Address with unlisted prefix is invalid', async () => {
    const result = isCash(
        'ecashdoge:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gtfza25mc',
    );
    expect(result).toStrictEqual(false);
});

test('toLegacy() converts a valid ecash: prefix address to a valid bitcoincash: prefix address', async () => {
    const result = toLegacy('ecash:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gtfza25mc');
    expect(result).toStrictEqual(
        'bitcoincash:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gjykk3wa0',
    );
});

test('toLegacy() accepts a valid BCH address with no prefix and returns with prefix', async () => {
    const result = toLegacy('qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gjykk3wa0');
    expect(result).toStrictEqual(
        'bitcoincash:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gjykk3wa0',
    );
});

test('toLegacy() returns a valid bitcoincash: prefix address unchanged', async () => {
    const result = toLegacy(
        'bitcoincash:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gjykk3wa0',
    );
    expect(result).toStrictEqual(
        'bitcoincash:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gjykk3wa0',
    );
});

test('toLegacy throws error if input address has invalid checksum', async () => {
    const result = toLegacy('ecash:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gtfza25m');

    expect(result).toStrictEqual(
        new ValidationError(
            'Invalid checksum: ecash:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gtfza25m.',
        ),
    );
});

test('toLegacy throws error if input address has invalid prefix', async () => {
    const result = toLegacy(
        'notecash:qqd3qn4zazjhygk5a2vzw2gvqgqwempr4gtfza25mc',
    );

    expect(result).toStrictEqual(
        new Error(
            'Address prefix is not a valid cash address with a prefix from the Ticker.prefixes array',
        ),
    );
});