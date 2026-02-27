import {
  createPublicClient,
  decodeEventLog,
  decodeFunctionResult,
  encodeAbiParameters,
  encodeFunctionData,
  formatEther,
  getAddress,
  hexToBytes,
  http,
  isAddress,
  parseAbiItem,
  zeroAddress,
} from 'viem';
import { gnosis } from 'viem/chains';
import { onWalletChange, sendTransactions } from '@aboutcircles/miniapp-sdk';
import { Sdk } from '@aboutcircles/sdk';
import { cidV0ToHex } from '@aboutcircles/sdk-utils';
import {
  getCompatibilityFallbackHandlerDeployment,
  getProxyFactoryDeployment,
  getSafeSingletonDeployment,
} from '@safe-global/safe-deployments';

/* ── Config ──────────────────────────────────────────────────────── */

const RPC_URL = 'https://rpc.aboutcircles.com/';
const RPC_FALLBACK_URLS = [
  RPC_URL,
  'https://rpc.gnosischain.com',
  'https://1rpc.io/gnosis',
];
const SAFE_VERSION = '1.4.1';
const OWNER_ORG_SAFE_MAP_KEY = 'circles-org-safe-by-owner-v1';
const TX_RECEIPT_TIMEOUT_MS = 12 * 60 * 1000;
const TX_RECEIPT_POLL_MS = 3000;
const ATTO_CIRCLES_DECIMALS = 18n;
const USER_OP_LOOKBACK_BLOCKS = 5000n;
const ENTRYPOINT_V07_ADDRESS = '0x0000000071727de22e5e9d8baf0edac6f37da032';
const HUB_V2_ADDRESS = '0xc12C1E50ABB450d6205Ea2C3Fa861b3B834d13e8';
const FAUCET_XDAI_ADDRESS = getAddress('0xbBD0173aafB8b52d6910DD3836dCFE85fc25CA8a');
const FAUCET_GROUP_TOKEN_ADDRESS = getAddress('0xc19bc204eb1c1d5b3fe500e5e5dfabab625f286c');
const FAUCET_CAP_WEI = 1_000_000_000_000_000_000n;
const FAUCET_PRICE_WEI = 10_000_000_000_000_000n;
const HUB_SAFE_TRANSFER_FROM_ABI = [
  {
    type: 'function',
    name: 'safeTransferFrom',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'from', type: 'address' },
      { name: 'to', type: 'address' },
      { name: 'id', type: 'uint256' },
      { name: 'value', type: 'uint256' },
      { name: 'data', type: 'bytes' },
    ],
    outputs: [],
  },
];
const HUB_FUNDING_CHECK_ABI = [
  {
    type: 'function',
    name: 'isHuman',
    stateMutability: 'view',
    inputs: [{ name: 'avatar', type: 'address' }],
    outputs: [{ type: 'bool' }],
  },
  {
    type: 'function',
    name: 'isTrusted',
    stateMutability: 'view',
    inputs: [
      { name: 'truster', type: 'address' },
      { name: 'trustee', type: 'address' },
    ],
    outputs: [{ type: 'bool' }],
  },
  {
    type: 'function',
    name: 'balanceOf',
    stateMutability: 'view',
    inputs: [
      { name: 'account', type: 'address' },
      { name: 'id', type: 'uint256' },
    ],
    outputs: [{ type: 'uint256' }],
  },
];
const FAUCET_FUNDING_CHECK_ABI = [
  {
    type: 'function',
    name: 'accountXDAIClaimed',
    stateMutability: 'view',
    inputs: [{ name: 'avatar', type: 'address' }],
    outputs: [{ type: 'uint256' }],
  },
];
const USER_OPERATION_EVENT = parseAbiItem(
  'event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)'
);
const PROXY_CREATION_EVENT = parseAbiItem(
  'event ProxyCreation(address indexed proxy, address singleton)'
);
const REGISTER_ORGANIZATION_EVENT = parseAbiItem(
  'event RegisterOrganization(address indexed organization, string name)'
);

const publicClient = createPublicClient({
  chain: gnosis,
  transport: http(RPC_URL),
});
const receiptClients = RPC_FALLBACK_URLS.map((url) =>
  createPublicClient({
    chain: gnosis,
    transport: http(url),
  })
);

const safeSingletonDeployment = getSafeSingletonDeployment({
  network: String(gnosis.id),
  version: SAFE_VERSION,
});
const proxyFactoryDeployment = getProxyFactoryDeployment({
  network: String(gnosis.id),
  version: SAFE_VERSION,
});
const compatibilityFallbackHandlerDeployment = getCompatibilityFallbackHandlerDeployment({
  network: String(gnosis.id),
  version: SAFE_VERSION,
});

/* ── State ───────────────────────────────────────────────────────── */

let connectedAddress = null;
let humanSdk = null;
let orgSdk = null;
let avatar = null;
let activeOrgAddress = null;
let lastTxHashes = [];
let cachedOrgBalances = [];
let cachedWithdrawableAttoCircles = 0n;
let activeSafeOwners = [];

/* ── DOM ─────────────────────────────────────────────────────────── */

const badge = document.getElementById('badge');
const resultEl = document.getElementById('result');

const loginSection = document.getElementById('login-section');
const optionsSection = document.getElementById('options-section');
const registerSection = document.getElementById('register-section');
const dashboardSection = document.getElementById('dashboard-section');
const startCreateOrgBtn = document.getElementById('start-create-org-btn');
const cancelRegisterBtn = document.getElementById('cancel-register-btn');
const optionsOrgList = document.getElementById('options-org-list');

const orgNameInput = document.getElementById('org-name');
const orgDescInput = document.getElementById('org-description');
const registerBtn = document.getElementById('register-btn');
const backToOptionsBtn = document.getElementById('back-to-options-btn');

const orgNameDisplay = document.getElementById('org-name-display');
const orgAddrDisplay = document.getElementById('org-address-display');
const trustAddrInput = document.getElementById('trust-address');
const addTrustBtn = document.getElementById('add-trust-btn');
const trustListEl = document.getElementById('trust-list');
const safeSignerAddressInput = document.getElementById('safe-signer-address');
const addSafeSignerBtn = document.getElementById('add-safe-signer-btn');
const safeSignersListEl = document.getElementById('safe-signers-list');
const fundFaucetHintEl = document.getElementById('fund-faucet-hint');
const fundRecipientAddressSelect = document.getElementById('fund-recipient-address');
const fundAmountXdaiInput = document.getElementById('fund-amount-xdai');
const fundFaucetBtn = document.getElementById('fund-faucet-btn');
const balancesEl = document.getElementById('balances-list');
const withdrawAvailableEl = document.getElementById('withdraw-available');
const withdrawTargetAddressInput = document.getElementById('withdraw-target-address');
const withdrawAmountInput = document.getElementById('withdraw-amount-circles');
const withdrawMaxBtn = document.getElementById('withdraw-max-btn');
const withdrawBalanceBtn = document.getElementById('withdraw-balance-btn');

/* ── Helpers ─────────────────────────────────────────────────────── */

function showResult(type, html) {
  resultEl.className = `result result-${type}`;
  resultEl.innerHTML = html;
  resultEl.classList.remove('hidden');
}

function hideResult() {
  resultEl.classList.add('hidden');
}

function setStatus(text, type) {
  badge.textContent = text;
  badge.className = `badge badge-${type}`;
}

function decodeError(err) {
  if (!err) return 'Unknown error';
  if (typeof err === 'string') return err;
  if (err.shortMessage) return err.shortMessage;
  if (err.message) return err.message;
  return String(err);
}

function isPasskeyAutoConnectError(err) {
  const message = decodeError(err).toLowerCase();
  return (
    message.includes('passkey') ||
    message.includes('passkeys') ||
    message.includes('auto connect') ||
    message.includes('autoconnect') ||
    (message.includes('wallet address') && message.includes('retrieve'))
  );
}

function truncAddr(a) {
  if (!a || a.length < 10) return a || '';
  return a.slice(0, 6) + '\u2026' + a.slice(-4);
}

function txLinks(hashes) {
  return hashes
    .map(
      (h) =>
        `<a href="https://gnosisscan.io/tx/${h}" target="_blank" rel="noopener">${h}</a>`
    )
    .join('<br>');
}

function formatNumberAmount(value) {
  if (!Number.isFinite(value)) return '0';
  if (value !== 0 && Math.abs(value) < 0.000001) return '<0.000001';
  return value.toLocaleString(undefined, { maximumFractionDigits: 6 });
}

function formatTokenBalanceAmount(balance) {
  const atto = getBalanceAttoCircles(balance);
  if (atto > 0n) return attoToCirclesString(atto);
  if (typeof balance?.circles === 'number') return formatNumberAmount(balance.circles);
  if (typeof balance?.crc === 'number') return formatNumberAmount(balance.crc);
  return '0';
}

function getBalanceAttoCircles(balance) {
  if (balance?.attoCircles === undefined || balance?.attoCircles === null) return 0n;
  const amount = BigInt(balance.attoCircles);
  if (amount > 0n) return amount;
  return 0n;
}

function sumWithdrawableAttoCircles(balances) {
  return balances.reduce((sum, balance) => sum + getBalanceAttoCircles(balance), 0n);
}

function attoToCirclesString(atto) {
  const formatted = formatEther(atto);
  return formatted.includes('.') ? formatted.replace(/\.?0+$/, '') : formatted;
}

function parseCirclesInputToAtto(value) {
  const trimmed = value.trim();
  if (!/^\d+(\.\d{1,18})?$/.test(trimmed)) return null;

  const [wholeRaw, fractionRaw = ''] = trimmed.split('.');
  const whole = BigInt(wholeRaw);
  const fraction = BigInt(fractionRaw.padEnd(Number(ATTO_CIRCLES_DECIMALS), '0'));
  return whole * 10n ** ATTO_CIRCLES_DECIMALS + fraction;
}

function estimateFaucetXdaiPayout(amountAttoCircles, alreadyClaimedWei) {
  if (alreadyClaimedWei >= FAUCET_CAP_WEI) return 0n;
  const remainingCap = FAUCET_CAP_WEI - alreadyClaimedWei;
  const maxAcceptedValue = remainingCap * FAUCET_CAP_WEI / FAUCET_PRICE_WEI;
  const acceptedValue = amountAttoCircles > maxAcceptedValue ? maxAcceptedValue : amountAttoCircles;
  return acceptedValue * FAUCET_PRICE_WEI / FAUCET_CAP_WEI;
}

function updateWithdrawAvailableText() {
  if (!withdrawAvailableEl) return;
  withdrawAvailableEl.textContent = `Available: ${attoToCirclesString(cachedWithdrawableAttoCircles)} CRC`;
}

function updateWithdrawButtonState() {
  const hasRecipientAddress = Boolean(withdrawTargetAddressInput?.value.trim());
  withdrawBalanceBtn.disabled = !hasRecipientAddress;
}

function hasAdditionalSafeSigner() {
  if (!connectedAddress || activeSafeOwners.length === 0) return false;
  return activeSafeOwners.some(
    (owner) => owner.toLowerCase() !== connectedAddress.toLowerCase()
  );
}

function getAdditionalSafeSignerAddresses() {
  if (!connectedAddress) return [];
  return activeSafeOwners.filter(
    (owner) => owner.toLowerCase() !== connectedAddress.toLowerCase()
  );
}

function renderFundRecipientOptions() {
  if (!fundRecipientAddressSelect) return;

  const recipients = getAdditionalSafeSignerAddresses();
  const currentValue = fundRecipientAddressSelect.value;

  if (recipients.length === 0) {
    fundRecipientAddressSelect.innerHTML = '<option value="">Add an EOA signer first</option>';
    fundRecipientAddressSelect.disabled = true;
    return;
  }

  const options = recipients
    .map((address) => `<option value="${address}">${address}</option>`)
    .join('');

  fundRecipientAddressSelect.innerHTML = options;
  fundRecipientAddressSelect.disabled = false;

  const normalizedCurrent = isAddress(currentValue) ? getAddress(currentValue) : null;
  if (normalizedCurrent && recipients.some((address) => address === normalizedCurrent)) {
    fundRecipientAddressSelect.value = normalizedCurrent;
  } else {
    fundRecipientAddressSelect.value = recipients[0];
  }
}

function updateFundFaucetButtonState() {
  const hasAdditionalSigner = hasAdditionalSafeSigner();
  const recipientAddressRaw = fundRecipientAddressSelect?.value.trim() || '';
  const recipientAddressValid = isAddress(recipientAddressRaw);
  const amountAttoCircles = parseCirclesInputToAtto(fundAmountXdaiInput?.value || '');
  const amountValid = amountAttoCircles !== null && amountAttoCircles > 0n;

  fundFaucetBtn.disabled = !(
    hasAdditionalSigner &&
    recipientAddressValid &&
    amountValid
  );

  if (!fundFaucetHintEl) return;
  if (!hasAdditionalSigner) {
    fundFaucetHintEl.textContent = 'Add at least one additional EOA signer to choose an xDAI recipient.';
    return;
  }
  fundFaucetHintEl.textContent = 'Mints required group CRC and sends it to the faucet, paying xDAI to the selected EOA.';
}

function hideAllSections() {
  loginSection.classList.add('hidden');
  optionsSection.classList.add('hidden');
  registerSection.classList.add('hidden');
  dashboardSection.classList.add('hidden');
}

function showDisconnectedState() {
  hideAllSections();
  hideResult();
  setStatus('Not connected', 'disconnected');
  registerBtn.disabled = true;
  safeSignersListEl.innerHTML = '<p class="muted">Connect a wallet to load signers.</p>';
  activeSafeOwners = [];
  cachedWithdrawableAttoCircles = 0n;
  renderFundRecipientOptions();
  updateWithdrawAvailableText();
  updateWithdrawButtonState();
  updateFundFaucetButtonState();
  loginSection.classList.remove('hidden');
}

function showCreateOrgOptions(ownerTypeLabel, orgSafes = []) {
  hideAllSections();
  setStatus('Logged in', 'success');
  renderOwnedOrgOptions(orgSafes);
  optionsSection.classList.remove('hidden');
}

function renderOwnedOrgOptions(orgSafes) {
  if (!orgSafes || orgSafes.length === 0) {
    optionsOrgList.innerHTML = '<p class="muted">No organizations yet.</p>';
    return;
  }

  optionsOrgList.innerHTML = orgSafes
    .map(
      (orgSafe) => `
      <div class="org-item">
        <a class="org-link mono" href="https://gnosisscan.io/address/${orgSafe}" target="_blank" rel="noopener">${orgSafe}</a>
        <button class="btn-sm org-open-btn" data-org-safe="${orgSafe}">Open</button>
      </div>
    `
    )
    .join('');

  optionsOrgList.querySelectorAll('.org-open-btn').forEach((btn) => {
    btn.addEventListener('click', () => openOwnedOrganization(btn.dataset.orgSafe));
  });
}

function toHexValue(value) {
  return value ? `0x${BigInt(value).toString(16)}` : '0x0';
}

function formatTxForHost(tx) {
  return {
    to: tx.to,
    data: tx.data || '0x',
    value: toHexValue(tx.value || 0n),
  };
}

function isOrganizationType(info) {
  const typeLower = (info?.type || info?.avatarType || '').toLowerCase();
  return typeLower.includes('organization') || typeLower.includes('org');
}

function getMapFromStorage() {
  try {
    const raw = localStorage.getItem(OWNER_ORG_SAFE_MAP_KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function setMapInStorage(map) {
  localStorage.setItem(OWNER_ORG_SAFE_MAP_KEY, JSON.stringify(map));
}

function normalizeStoredOrgSafes(value) {
  const values = Array.isArray(value) ? value : [value];
  const seen = new Set();
  const out = [];

  for (const candidate of values) {
    if (typeof candidate !== 'string' || !isAddress(candidate)) continue;
    const normalized = getAddress(candidate);
    const key = normalized.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(normalized);
  }

  return out;
}

function getStoredOrgSafes(ownerAddress) {
  const map = getMapFromStorage();
  const value = map[ownerAddress.toLowerCase()];
  return normalizeStoredOrgSafes(value);
}

function setStoredOrgSafes(ownerAddress, orgSafeAddresses) {
  const map = getMapFromStorage();
  map[ownerAddress.toLowerCase()] = normalizeStoredOrgSafes(orgSafeAddresses);
  setMapInStorage(map);
}

function addStoredOrgSafe(ownerAddress, orgSafeAddress) {
  const existing = getStoredOrgSafes(ownerAddress);
  existing.push(getAddress(orgSafeAddress));
  setStoredOrgSafes(ownerAddress, existing);
}

function removeStoredOrgSafe(ownerAddress, orgSafeAddress) {
  const map = getMapFromStorage();
  if (!orgSafeAddress) {
    delete map[ownerAddress.toLowerCase()];
    setMapInStorage(map);
    return;
  }

  const remaining = normalizeStoredOrgSafes(map[ownerAddress.toLowerCase()]).filter(
    (safe) => safe.toLowerCase() !== orgSafeAddress.toLowerCase()
  );

  if (remaining.length === 0) delete map[ownerAddress.toLowerCase()];
  else map[ownerAddress.toLowerCase()] = remaining;
  setMapInStorage(map);
}

function getDeploymentAddress(deployment) {
  if (!deployment) throw new Error('Safe deployment metadata is missing.');
  const networkAddress = deployment.networkAddresses?.[String(gnosis.id)] || deployment.defaultAddress;
  if (!networkAddress) {
    throw new Error('Safe deployment for this network is missing.');
  }
  return getAddress(networkAddress);
}

function randomSaltNonce() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let value = 0n;
  for (const b of bytes) value = (value << 8n) + BigInt(b);
  return value.toString();
}

function buildPrevalidatedSignature(ownerAddress) {
  const ownerPadded = ownerAddress.toLowerCase().replace('0x', '').padStart(64, '0');
  return `0x${ownerPadded}${'0'.repeat(64)}01`;
}

async function waitForReceipts(hashes) {
  const receipts = [];
  for (const hash of hashes) {
    receipts.push(await waitForReceiptFromAnyRpc(hash));
  }
  return receipts;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForReceiptFromAnyRpc(hash) {
  const deadline = Date.now() + TX_RECEIPT_TIMEOUT_MS;
  let lastErrorMessage = '';
  let round = 0;

  while (Date.now() < deadline) {
    round += 1;

    for (const client of receiptClients) {
      try {
        const receipt = await client.getTransactionReceipt({ hash });
        if (receipt) return receipt;
      } catch (err) {
        lastErrorMessage = decodeError(err);
      }
    }

    if (round % 2 === 0) {
      for (const client of receiptClients) {
        const receipt = await tryResolveUserOpReceipt(client, hash);
        if (receipt) return receipt;
      }
    }

    await sleep(TX_RECEIPT_POLL_MS);
  }

  const detail = lastErrorMessage ? ` Last RPC error: ${lastErrorMessage}` : '';
  throw new Error(
    `Timed out while waiting for transaction with hash "${hash}" to be confirmed.${detail}`
  );
}

async function tryResolveUserOpReceipt(client, userOpHash) {
  try {
    const latest = await client.getBlockNumber();
    const fromBlock = latest > USER_OP_LOOKBACK_BLOCKS ? latest - USER_OP_LOOKBACK_BLOCKS : 0n;

    const logs = await client.getLogs({
      address: ENTRYPOINT_V07_ADDRESS,
      event: USER_OPERATION_EVENT,
      args: { userOpHash },
      fromBlock,
      toBlock: latest,
    });

    if (!logs || logs.length === 0) return null;
    const txHash = logs[logs.length - 1]?.transactionHash;
    if (!txHash) return null;

    return await client.getTransactionReceipt({ hash: txHash });
  } catch {
    return null;
  }
}

async function preflightEthCall({ label, to, data = '0x', value = 0n, account }) {
  try {
    await publicClient.call({
      to: getAddress(to),
      data,
      value: BigInt(value),
      account,
    });
  } catch (err) {
    throw new Error(`${label} preflight failed: ${decodeError(err)}`);
  }
}

function assertSafeExecutionSuccess(receipt, safeAddress, safeAbi) {
  let sawSuccess = false;

  for (const log of receipt.logs) {
    if (!log.address || log.address.toLowerCase() !== safeAddress.toLowerCase()) continue;

    try {
      const decoded = decodeEventLog({
        abi: safeAbi,
        data: log.data,
        topics: log.topics,
        strict: false,
      });

      if (decoded?.eventName === 'ExecutionFailure') {
        throw new Error('Safe execution failed.');
      }

      if (decoded?.eventName === 'ExecutionSuccess') {
        sawSuccess = true;
      }
    } catch (err) {
      if (err?.message === 'Safe execution failed.') throw err;
    }
  }

  if (!sawSuccess) {
    throw new Error('Safe execution status could not be confirmed.');
  }
}

function deriveOrganizationAddressFromReceipts(receipts, proxyFactoryAddress, hubAddress) {
  let proxyAddress = null;
  let registeredOrgAddress = null;

  for (const receipt of receipts) {
    for (const log of receipt.logs) {
      if (!log.address) continue;

      if (log.address.toLowerCase() === proxyFactoryAddress.toLowerCase()) {
        try {
          const decoded = decodeEventLog({
            abi: [PROXY_CREATION_EVENT],
            data: log.data,
            topics: log.topics,
            strict: false,
          });
          if (decoded?.eventName === 'ProxyCreation' && decoded.args?.proxy) {
            proxyAddress = getAddress(decoded.args.proxy);
          }
        } catch {}
      }

      if (log.address.toLowerCase() === hubAddress.toLowerCase()) {
        try {
          const decoded = decodeEventLog({
            abi: [REGISTER_ORGANIZATION_EVENT],
            data: log.data,
            topics: log.topics,
            strict: false,
          });
          if (decoded?.eventName === 'RegisterOrganization' && decoded.args?.organization) {
            registeredOrgAddress = getAddress(decoded.args.organization);
          }
        } catch {}
      }
    }
  }

  return registeredOrgAddress || proxyAddress || null;
}


/* ── ContractRunner Bridges ──────────────────────────────────────── */

function createRunner(address) {
  return {
    address,
    async sendTransaction(txs) {
      const hashes = await sendTransactions(txs.map(formatTxForHost));
      lastTxHashes = hashes;
      const receipts = await waitForReceipts(hashes);
      return receipts[receipts.length - 1];
    },
  };
}

function createSafeOwnerRunner(ownerAddress, safeAddress) {
  const safeAbi = safeSingletonDeployment?.abi;
  if (!safeAbi) throw new Error('Safe singleton ABI is unavailable.');

  return {
    address: safeAddress,
    async sendTransaction(txs) {
      const signature = buildPrevalidatedSignature(ownerAddress);

      const safeExecTxs = txs.map((tx) => ({
        to: safeAddress,
        value: 0n,
        data: encodeFunctionData({
          abi: safeAbi,
          functionName: 'execTransaction',
          args: [
            tx.to,
            tx.value ? BigInt(tx.value) : 0n,
            tx.data || '0x',
            0,
            0n,
            0n,
            0n,
            zeroAddress,
            zeroAddress,
            signature,
          ],
        }),
      }));

      const hashes = await sendTransactions(safeExecTxs.map(formatTxForHost));
      lastTxHashes = hashes;

      const receipts = await waitForReceipts(hashes);
      receipts.forEach((receipt) => assertSafeExecutionSuccess(receipt, safeAddress, safeAbi));

      return receipts[receipts.length - 1];
    },
  };
}

/* ── Register Organization ───────────────────────────────────────── */

async function registerOrganization() {
  const name = orgNameInput.value.trim();
  if (!name) {
    showResult('error', 'Organization name is required.');
    return;
  }

  if (!connectedAddress || !humanSdk) {
    showResult('error', 'Connect a wallet first.');
    return;
  }

  registerBtn.disabled = true;
  showResult('pending', 'Preparing Safe deployment and org registration…');

  try {
    lastTxHashes = [];

    const safeAbi = safeSingletonDeployment?.abi;
    if (!safeAbi) {
      throw new Error('Safe deployment metadata unavailable.');
    }
    const proxyFactoryAbi = proxyFactoryDeployment?.abi;
    if (!proxyFactoryAbi) {
      throw new Error('Safe proxy factory deployment metadata unavailable.');
    }

    const profile = { name };
    const desc = orgDescInput.value.trim();
    if (desc) profile.description = desc;

    const profileCid = await humanSdk.profilesClient.create(profile);
    const metadataDigest = cidV0ToHex(profileCid);

    const saltNonce = randomSaltNonce();
    const safeSingletonAddress = getDeploymentAddress(safeSingletonDeployment);
    const proxyFactoryAddress = getDeploymentAddress(proxyFactoryDeployment);
    const fallbackHandlerAddress = getDeploymentAddress(compatibilityFallbackHandlerDeployment);

    const setupData = encodeFunctionData({
      abi: safeAbi,
      functionName: 'setup',
      args: [
        [connectedAddress],
        1n,
        zeroAddress,
        '0x',
        fallbackHandlerAddress,
        zeroAddress,
        0n,
        zeroAddress,
      ],
    });
    const deploySafeData = encodeFunctionData({
      abi: proxyFactoryAbi,
      functionName: 'createProxyWithNonce',
      args: [safeSingletonAddress, setupData, BigInt(saltNonce)],
    });

    const deploymentPreflight = await publicClient.call({
      to: proxyFactoryAddress,
      data: deploySafeData,
      account: connectedAddress,
    });
    const predictedOrgSafe = getAddress(
      decodeFunctionResult({
        abi: proxyFactoryAbi,
        functionName: 'createProxyWithNonce',
        data: deploymentPreflight.data,
      })
    );

    const registerTx = humanSdk.core.hubV2.registerOrganization(name, metadataDigest);
    const safeExecData = encodeFunctionData({
      abi: safeAbi,
      functionName: 'execTransaction',
      args: [
        registerTx.to,
        registerTx.value || 0n,
        registerTx.data || '0x',
        0,
        0n,
        0n,
        0n,
        zeroAddress,
        zeroAddress,
        buildPrevalidatedSignature(connectedAddress),
      ],
    });

    showResult('pending', 'Running preflight eth_call checks…');
    await preflightEthCall({
      label: 'Organization registration',
      to: registerTx.to,
      data: registerTx.data || '0x',
      value: registerTx.value || 0n,
      account: predictedOrgSafe,
    });

    showResult('pending', 'Deploying dedicated Safe and registering organization (single batched approval)…');
    const txHashes = await sendTransactions([
      formatTxForHost({
        to: proxyFactoryAddress,
        data: deploySafeData,
        value: 0n,
      }),
      formatTxForHost({
        to: predictedOrgSafe,
        data: safeExecData,
        value: 0n,
      }),
    ]);

    lastTxHashes = txHashes;

    let receipts;
    try {
      receipts = await waitForReceipts(txHashes);
    } catch (err) {
      const maybeOrgInfo = await humanSdk.data.getAvatar(predictedOrgSafe).catch(() => null);
      if (!isOrganizationType(maybeOrgInfo)) throw err;

      addStoredOrgSafe(connectedAddress, predictedOrgSafe);

      const links = lastTxHashes.length ? `<br>${txLinks(lastTxHashes)}` : '';
      showResult(
        'success',
        `Organization registered via dedicated Safe: <a href="https://gnosisscan.io/address/${predictedOrgSafe}" target="_blank" rel="noopener">${predictedOrgSafe}</a><br><span class="muted">Receipt polling timed out, but on-chain state confirms registration.</span>${links}`
      );

      await loadAvatarState(true);
      return;
    }

    const resolvedOrgSafe =
      deriveOrganizationAddressFromReceipts(receipts, proxyFactoryAddress, registerTx.to) ||
      predictedOrgSafe;

    const safeExecReceipts = receipts.filter((receipt) =>
      receipt.logs.some(
        (log) => log.address && log.address.toLowerCase() === resolvedOrgSafe.toLowerCase()
      )
    );

    if (safeExecReceipts.length === 0) {
      throw new Error('Safe execution transaction could not be verified.');
    }

    safeExecReceipts.forEach((receipt) =>
      assertSafeExecutionSuccess(receipt, resolvedOrgSafe, safeAbi)
    );

    const newOrgInfo = await humanSdk.data.getAvatar(resolvedOrgSafe);
    if (!isOrganizationType(newOrgInfo)) {
      throw new Error('Safe deployed, but org registration was not confirmed.');
    }

    addStoredOrgSafe(connectedAddress, resolvedOrgSafe);

    const links = lastTxHashes.length ? `<br>${txLinks(lastTxHashes)}` : '';
    showResult(
      'success',
      `Organization registered via dedicated Safe: <a href="https://gnosisscan.io/address/${resolvedOrgSafe}" target="_blank" rel="noopener">${resolvedOrgSafe}</a>${links}`
    );

    await loadAvatarState(true);
  } catch (err) {
    if (isPasskeyAutoConnectError(err)) {
      showResult(
        'error',
        'Passkey auto-connect failed in the host app. Re-open wallet connect and choose the same wallet again, then retry organization creation.'
      );
    } else {
      showResult('error', `Registration failed: ${decodeError(err)}`);
    }
  } finally {
    registerBtn.disabled = false;
  }
}

/* ── Safe Signers ────────────────────────────────────────────────── */

async function loadSafeSigners() {
  if (!activeOrgAddress) {
    activeSafeOwners = [];
    safeSignersListEl.innerHTML = '<p class="muted">No organization selected.</p>';
    renderFundRecipientOptions();
    updateFundFaucetButtonState();
    return;
  }

  const safeAbi = safeSingletonDeployment?.abi;
  if (!safeAbi) {
    activeSafeOwners = [];
    safeSignersListEl.innerHTML = '<p class="muted">Safe ABI unavailable.</p>';
    renderFundRecipientOptions();
    updateFundFaucetButtonState();
    return;
  }

  safeSignersListEl.innerHTML = '<p class="muted">Loading signers…</p>';

  try {
    const owners = await publicClient.readContract({
      address: getAddress(activeOrgAddress),
      abi: safeAbi,
      functionName: 'getOwners',
    });
    const threshold = await publicClient.readContract({
      address: getAddress(activeOrgAddress),
      abi: safeAbi,
      functionName: 'getThreshold',
    });

    if (!owners || owners.length === 0) {
      activeSafeOwners = [];
      safeSignersListEl.innerHTML = '<p class="muted">No signers found.</p>';
      renderFundRecipientOptions();
      updateFundFaucetButtonState();
      return;
    }

    activeSafeOwners = owners.map((owner) => getAddress(owner));
    const thresholdValue = BigInt(threshold).toString();
    const rows = activeSafeOwners
      .map((owner) => {
        const isConnected = connectedAddress && owner.toLowerCase() === connectedAddress.toLowerCase();
        return `<div class="trust-item"><span class="mono">${owner}</span><span class="muted">${isConnected ? 'Connected' : 'Signer'}</span></div>`;
      })
      .join('');

    safeSignersListEl.innerHTML = `<p class="muted">Threshold: ${thresholdValue}</p>${rows}`;
    renderFundRecipientOptions();
    updateFundFaucetButtonState();
  } catch (err) {
    activeSafeOwners = [];
    safeSignersListEl.innerHTML = `<p class="muted">Could not load signers: ${decodeError(err)}</p>`;
    renderFundRecipientOptions();
    updateFundFaucetButtonState();
  }
}

async function addSafeSigner() {
  const rawAddress = safeSignerAddressInput.value.trim();
  if (!isAddress(rawAddress)) {
    showResult('error', 'Enter a valid signer address.');
    return;
  }

  if (!activeOrgAddress || !connectedAddress) {
    showResult('error', 'Organization wallet is not ready.');
    return;
  }

  const safeAbi = safeSingletonDeployment?.abi;
  if (!safeAbi) {
    showResult('error', 'Safe ABI unavailable.');
    return;
  }

  const signerToAdd = getAddress(rawAddress);
  addSafeSignerBtn.disabled = true;
  showResult('pending', 'Adding signer…');

  try {
    const owners = await publicClient.readContract({
      address: getAddress(activeOrgAddress),
      abi: safeAbi,
      functionName: 'getOwners',
    });
    const threshold = await publicClient.readContract({
      address: getAddress(activeOrgAddress),
      abi: safeAbi,
      functionName: 'getThreshold',
    });

    if (owners.some((owner) => owner.toLowerCase() === signerToAdd.toLowerCase())) {
      showResult('error', 'Address is already a signer.');
      return;
    }

    if (!owners.some((owner) => owner.toLowerCase() === connectedAddress.toLowerCase())) {
      showResult('error', 'Connected wallet is not an owner of this Safe.');
      return;
    }

    const addSignerData = encodeFunctionData({
      abi: safeAbi,
      functionName: 'addOwnerWithThreshold',
      args: [signerToAdd, BigInt(threshold)],
    });

    const runner = createSafeOwnerRunner(connectedAddress, getAddress(activeOrgAddress));
    lastTxHashes = [];
    await runner.sendTransaction([
      {
        to: getAddress(activeOrgAddress),
        data: addSignerData,
        value: 0n,
      },
    ]);

    const links = lastTxHashes.length ? `<br>${txLinks(lastTxHashes)}` : '';
    showResult('success', `Added signer ${signerToAdd}.${links}`);
    safeSignerAddressInput.value = '';
    await loadSafeSigners();
  } catch (err) {
    showResult('error', `Add signer failed: ${decodeError(err)}`);
  } finally {
    addSafeSignerBtn.disabled = false;
  }
}

async function fundFaucetXdai() {
  const rawRecipientAddress = fundRecipientAddressSelect?.value.trim() || '';
  if (!isAddress(rawRecipientAddress)) {
    showResult('error', 'Choose a valid recipient EOA address.');
    return;
  }

  const amountAttoCircles = parseCirclesInputToAtto(fundAmountXdaiInput.value);
  if (amountAttoCircles === null || amountAttoCircles <= 0n) {
    showResult('error', 'Enter a valid CRC amount.');
    return;
  }

  if (!humanSdk || !connectedAddress) {
    showResult('error', 'Connected account is not ready.');
    return;
  }

  if (!hasAdditionalSafeSigner()) {
    showResult('error', 'Add an additional EOA signer before funding.');
    return;
  }

  const faucetAddress = FAUCET_XDAI_ADDRESS;
  const groupTokenAddress = FAUCET_GROUP_TOKEN_ADDRESS;
  const recipientAddress = getAddress(rawRecipientAddress);
  const senderAddress = getAddress(connectedAddress);
  const groupTokenId = BigInt(groupTokenAddress);
  const payoutDataHex = encodeAbiParameters([{ type: 'address' }], [recipientAddress]);

  fundFaucetBtn.disabled = true;
  showResult('pending', 'Preparing group CRC for faucet transfer…');

  try {
    const [isHuman, isTrusted, senderGroupCrcBalance, claimedXdai, faucetXdaiBalance] =
      await Promise.all([
        publicClient.readContract({
          address: getAddress(HUB_V2_ADDRESS),
          abi: HUB_FUNDING_CHECK_ABI,
          functionName: 'isHuman',
          args: [senderAddress],
        }),
        publicClient.readContract({
          address: getAddress(HUB_V2_ADDRESS),
          abi: HUB_FUNDING_CHECK_ABI,
          functionName: 'isTrusted',
          args: [faucetAddress, groupTokenAddress],
        }),
        publicClient.readContract({
          address: getAddress(HUB_V2_ADDRESS),
          abi: HUB_FUNDING_CHECK_ABI,
          functionName: 'balanceOf',
          args: [senderAddress, groupTokenId],
        }),
        publicClient.readContract({
          address: faucetAddress,
          abi: FAUCET_FUNDING_CHECK_ABI,
          functionName: 'accountXDAIClaimed',
          args: [senderAddress],
        }),
        publicClient.getBalance({ address: faucetAddress }),
      ]);
    const recipientCode = await publicClient.getCode({ address: recipientAddress });

    if (!isHuman) {
      throw new Error('Connected account must be a Human avatar to claim xDAI from faucet.');
    }
    if (recipientCode && recipientCode !== '0x') {
      throw new Error('Recipient must be an EOA address (no contract code).');
    }
    if (!isTrusted) {
      throw new Error(
        `Faucet does not trust required group token ${groupTokenAddress}.`
      );
    }

    const estimatedPayoutWei = estimateFaucetXdaiPayout(amountAttoCircles, claimedXdai);
    if (estimatedPayoutWei <= 0n) {
      throw new Error('Faucet cap reached for this human avatar.');
    }
    if (faucetXdaiBalance < estimatedPayoutWei) {
      throw new Error(
        `Faucet has insufficient xDAI liquidity for this claim. Needs ${attoToCirclesString(estimatedPayoutWei)} xDAI.`
      );
    }

    const senderAvatar = await humanSdk.getAvatar(senderAddress);
    const txHashes = [];
    const requiredMintAmount =
      amountAttoCircles > senderGroupCrcBalance ? amountAttoCircles - senderGroupCrcBalance : 0n;

    if (requiredMintAmount > 0n) {
      const maxMintable = await senderAvatar.groupToken.getMaxMintableAmount(groupTokenAddress);
      if (maxMintable < requiredMintAmount) {
        throw new Error(
          `Not enough mintable group CRC. Need ${attoToCirclesString(requiredMintAmount)} CRC, max mintable is ${attoToCirclesString(maxMintable)} CRC.`
        );
      }

      showResult(
        'pending',
        `Minting ${attoToCirclesString(requiredMintAmount)} CRC from group ${groupTokenAddress}…`
      );
      lastTxHashes = [];
      await senderAvatar.groupToken.mint(groupTokenAddress, requiredMintAmount);
      txHashes.push(...lastTxHashes);
    }

    const availableGroupCrc = await publicClient.readContract({
      address: getAddress(HUB_V2_ADDRESS),
      abi: HUB_FUNDING_CHECK_ABI,
      functionName: 'balanceOf',
      args: [senderAddress, groupTokenId],
    });
    if (availableGroupCrc < amountAttoCircles) {
      throw new Error(
        `Insufficient group CRC after mint. Available ${attoToCirclesString(availableGroupCrc)} CRC, required ${attoToCirclesString(amountAttoCircles)} CRC.`
      );
    }

    const preflightData = encodeFunctionData({
      abi: HUB_SAFE_TRANSFER_FROM_ABI,
      functionName: 'safeTransferFrom',
      args: [senderAddress, faucetAddress, groupTokenId, amountAttoCircles, payoutDataHex],
    });

    showResult('pending', 'Sending group CRC to faucet…');
    await preflightEthCall({
      label: 'CRC transfer to faucet',
      to: HUB_V2_ADDRESS,
      data: preflightData,
      value: 0n,
      account: senderAddress,
    });

    lastTxHashes = [];
    await senderAvatar.transfer.direct(
      faucetAddress,
      amountAttoCircles,
      groupTokenAddress,
      hexToBytes(payoutDataHex)
    );
    txHashes.push(...lastTxHashes);
    lastTxHashes = txHashes;

    const links = lastTxHashes.length ? `<br>${txLinks(lastTxHashes)}` : '';
    showResult(
      'success',
      `Sent ${attoToCirclesString(amountAttoCircles)} CRC (${groupTokenAddress}) to faucet ${faucetAddress}. Recipient EOA: ${recipientAddress}.${links}`
    );
  } catch (err) {
    showResult('error', `CRC-to-xDAI funding failed: ${decodeError(err)}`);
  } finally {
    updateFundFaucetButtonState();
  }
}

/* ── Trust Management ────────────────────────────────────────────── */

async function addTrust() {
  const raw = trustAddrInput.value.trim();
  if (!isAddress(raw)) {
    showResult('error', 'Enter a valid address.');
    return;
  }

  if (!avatar) {
    showResult('error', 'Organization wallet is not ready.');
    return;
  }

  const addr = getAddress(raw);

  addTrustBtn.disabled = true;
  showResult('pending', 'Requesting approval…');

  try {
    lastTxHashes = [];
    await avatar.trust.add(addr);

    const links = lastTxHashes.length ? `<br>${txLinks(lastTxHashes)}` : '';
    showResult('success', `Now trusting ${truncAddr(addr)}.${links}`);
    trustAddrInput.value = '';
    await loadTrustRelations();
  } catch (err) {
    showResult('error', `Trust failed: ${decodeError(err)}`);
  } finally {
    addTrustBtn.disabled = false;
  }
}

async function removeTrust(addr) {
  const btns = trustListEl.querySelectorAll(`[data-addr="${addr}"]`);
  btns.forEach((b) => (b.disabled = true));
  showResult('pending', 'Requesting approval…');

  try {
    lastTxHashes = [];
    await avatar.trust.remove(addr);

    const links = lastTxHashes.length ? `<br>${txLinks(lastTxHashes)}` : '';
    showResult('success', `Removed trust for ${truncAddr(addr)}.${links}`);
    await loadTrustRelations();
  } catch (err) {
    showResult('error', `Untrust failed: ${decodeError(err)}`);
    btns.forEach((b) => (b.disabled = false));
  }
}

function fillWithdrawMax() {
  if (cachedWithdrawableAttoCircles <= 0n) return;
  withdrawAmountInput.value = attoToCirclesString(cachedWithdrawableAttoCircles);
}

async function withdrawBalance() {
  const rawRecipient = withdrawTargetAddressInput.value.trim();
  if (!isAddress(rawRecipient)) {
    showResult('error', 'Enter a valid recipient address.');
    return;
  }

  const parsedAmount = parseCirclesInputToAtto(withdrawAmountInput.value);
  if (parsedAmount === null || parsedAmount <= 0n) {
    showResult('error', 'Enter a valid CRC amount.');
    return;
  }

  if (!avatar) {
    showResult('error', 'Organization wallet is not ready.');
    return;
  }

  if (cachedWithdrawableAttoCircles === 0n) {
    await loadBalances();
  }

  if (cachedWithdrawableAttoCircles === 0n) {
    showResult('error', 'No withdrawable CRC balance.');
    return;
  }

  if (parsedAmount > cachedWithdrawableAttoCircles) {
    showResult(
      'error',
      `Requested amount exceeds available balance (${attoToCirclesString(cachedWithdrawableAttoCircles)} CRC).`
    );
    return;
  }

  const recipient = getAddress(rawRecipient);
  withdrawBalanceBtn.disabled = true;
  showResult('pending', 'Requesting approval…');

  try {
    lastTxHashes = [];
    await avatar.transfer.advanced(recipient, parsedAmount);

    const links = lastTxHashes.length ? `<br>${txLinks(lastTxHashes)}` : '';
    showResult(
      'success',
      `Withdrew ${attoToCirclesString(parsedAmount)} CRC to ${recipient}.${links}`
    );

    withdrawAmountInput.value = '';
    await loadBalances();
  } catch (err) {
    showResult('error', `Withdraw failed: ${decodeError(err)}`);
  } finally {
    updateWithdrawButtonState();
  }
}

/* ── Data Loading ────────────────────────────────────────────────── */

async function loadTrustRelations() {
  trustListEl.innerHTML = '<p class="muted">Loading…</p>';

  if (!orgSdk || !activeOrgAddress) {
    trustListEl.innerHTML = '<p class="muted">No organization selected.</p>';
    return;
  }

  try {
    const relations = await orgSdk.data.getTrustRelations(activeOrgAddress);

    if (!relations || relations.length === 0) {
      trustListEl.innerHTML = '<p class="muted">No trust relations yet.</p>';
      return;
    }

    trustListEl.innerHTML = relations
      .map((r) => {
        const addr =
          r.objectAvatar || r.trustee || r.address || (typeof r === 'string' ? r : '');
        return `
          <div class="trust-item">
            <a class="trust-addr" href="https://gnosisscan.io/address/${addr}" target="_blank" title="${addr}">${truncAddr(addr)}</a>
            <button class="btn-sm btn-danger" data-addr="${addr}">Untrust</button>
          </div>`;
      })
      .join('');

    trustListEl.querySelectorAll('.btn-danger').forEach((btn) => {
      btn.addEventListener('click', () => removeTrust(btn.dataset.addr));
    });
  } catch (err) {
    trustListEl.innerHTML = `<p class="muted">Error loading trust: ${decodeError(err)}</p>`;
  }
}

async function loadBalances() {
  if (balancesEl) balancesEl.innerHTML = '<p class="muted">Loading…</p>';

  if (!avatar) {
    cachedOrgBalances = [];
    cachedWithdrawableAttoCircles = 0n;
    updateWithdrawAvailableText();
    if (balancesEl) balancesEl.innerHTML = '<p class="muted">No organization selected.</p>';
    return;
  }

  try {
    const balances = await avatar.balances.getTokenBalances();
    cachedOrgBalances = balances;
    cachedWithdrawableAttoCircles = sumWithdrawableAttoCircles(balances);
    updateWithdrawAvailableText();

    if (!balances || balances.length === 0) {
      if (balancesEl) balancesEl.innerHTML = '<p class="muted">No token balances.</p>';
      return;
    }

    if (balancesEl) {
      balancesEl.innerHTML = balances
        .map((b) => {
          const label =
            b.symbol || b.tokenSymbol || truncAddr(b.tokenAddress || b.token || '');
          const amount = formatTokenBalanceAmount(b);
          return `<div class="balance-item"><span>${label}</span><span>${amount} CRC</span></div>`;
        })
        .join('');
    }
  } catch (err) {
    cachedOrgBalances = [];
    cachedWithdrawableAttoCircles = 0n;
    updateWithdrawAvailableText();
    if (balancesEl) balancesEl.innerHTML = `<p class="muted">Error: ${decodeError(err)}</p>`;
  }
}

async function loadOrganizationDashboard(orgAddress, runner, statusLabel) {
  activeOrgAddress = orgAddress;
  orgSdk = new Sdk(undefined, runner);
  avatar = await orgSdk.getAvatar(orgAddress);

  setStatus(statusLabel, 'success');
  dashboardSection.classList.remove('hidden');

  try {
    const profile = await avatar.profile.get();
    orgNameDisplay.textContent = profile?.name || '—';
  } catch {
    orgNameDisplay.textContent = '—';
  }

  orgAddrDisplay.textContent = orgAddress;
  if (connectedAddress && connectedAddress.toLowerCase() !== orgAddress.toLowerCase()) {
    backToOptionsBtn.classList.remove('hidden');
  } else {
    backToOptionsBtn.classList.add('hidden');
  }

  await Promise.allSettled([loadSafeSigners(), loadTrustRelations(), loadBalances()]);
}

async function openOwnedOrganization(orgSafeAddress) {
  if (!connectedAddress || !humanSdk) return;

  hideAllSections();
  showResult('pending', `Opening organization ${truncAddr(orgSafeAddress)}…`);

  try {
    await loadOrganizationDashboard(
      orgSafeAddress,
      createSafeOwnerRunner(connectedAddress, orgSafeAddress),
      'Organization (Owned Safe)'
    );
    hideResult();
  } catch (err) {
    showResult('error', `Could not open organization: ${decodeError(err)}`);
  }
}

/* ── Avatar State ────────────────────────────────────────────────── */

async function loadAvatarState(preserveResult = false) {
  if (!connectedAddress || !humanSdk) return;

  hideAllSections();
  if (!preserveResult) hideResult();

  avatar = null;
  orgSdk = null;
  activeOrgAddress = null;
  activeSafeOwners = [];
  cachedOrgBalances = [];
  cachedWithdrawableAttoCircles = 0n;
  renderFundRecipientOptions();
  updateWithdrawAvailableText();
  updateFundFaucetButtonState();

  try {
    const connectedInfo = await humanSdk.data.getAvatar(connectedAddress);

    if (isOrganizationType(connectedInfo)) {
      await loadOrganizationDashboard(
        connectedAddress,
        createRunner(connectedAddress),
        'Organization'
      );
      return;
    }

    const ownerTypeLabel = connectedInfo?.type || connectedInfo?.avatarType || 'Not registered';
    const storedOrgSafes = getStoredOrgSafes(connectedAddress);
    const validOwnedOrgSafes = [];

    for (const safe of storedOrgSafes) {
      try {
        const info = await humanSdk.data.getAvatar(safe);
        if (isOrganizationType(info)) validOwnedOrgSafes.push(safe);
      } catch {
        // Skip stale entries.
      }
    }

    if (validOwnedOrgSafes.length !== storedOrgSafes.length) {
      setStoredOrgSafes(connectedAddress, validOwnedOrgSafes);
    }

    showCreateOrgOptions(ownerTypeLabel, validOwnedOrgSafes);
  } catch {
    const fallbackSafes = connectedAddress ? getStoredOrgSafes(connectedAddress) : [];
    showCreateOrgOptions('Not registered', fallbackSafes);
  }
}

/* ── Wallet Listener ─────────────────────────────────────────────── */

onWalletChange(async (address) => {
  try {
    connectedAddress = address ? getAddress(address) : null;
  } catch {
    connectedAddress = null;
  }

  avatar = null;
  orgSdk = null;
  humanSdk = null;
  activeOrgAddress = null;
  activeSafeOwners = [];
  lastTxHashes = [];
  cachedOrgBalances = [];
  cachedWithdrawableAttoCircles = 0n;
  renderFundRecipientOptions();
  updateWithdrawAvailableText();
  updateFundFaucetButtonState();

  hideAllSections();
  hideResult();

  if (!connectedAddress) {
    showDisconnectedState();
    return;
  }

  setStatus('Checking…', 'pending');

  try {
    humanSdk = new Sdk(undefined, createRunner(connectedAddress));
    await loadAvatarState();
  } catch (err) {
    if (isPasskeyAutoConnectError(err)) {
      setStatus('Wallet reconnect required', 'warning');
      showResult(
        'error',
        'Passkey auto-connect failed in the host app. Re-open wallet connect and choose your wallet again.'
      );
    } else {
      setStatus('Connection error', 'error');
      showResult('error', `Wallet initialization failed: ${decodeError(err)}`);
    }
  }
});

if (typeof window !== 'undefined') {
  window.addEventListener('unhandledrejection', (event) => {
    if (!isPasskeyAutoConnectError(event.reason)) return;
    setStatus('Wallet reconnect required', 'warning');
    showResult(
      'error',
      'Passkey auto-connect failed in the host app. Re-open wallet connect and choose your wallet again.'
    );
  });

  window.addEventListener('error', (event) => {
    if (!isPasskeyAutoConnectError(event.error || event.message)) return;
    setStatus('Wallet reconnect required', 'warning');
    showResult(
      'error',
      'Passkey auto-connect failed in the host app. Re-open wallet connect and choose your wallet again.'
    );
  });
}

/* ── Event Listeners ─────────────────────────────────────────────── */

registerBtn.addEventListener('click', registerOrganization);
addTrustBtn.addEventListener('click', addTrust);
addSafeSignerBtn.addEventListener('click', addSafeSigner);
fundFaucetBtn.addEventListener('click', fundFaucetXdai);
withdrawMaxBtn.addEventListener('click', fillWithdrawMax);
withdrawBalanceBtn.addEventListener('click', withdrawBalance);
withdrawTargetAddressInput.addEventListener('input', updateWithdrawButtonState);
fundAmountXdaiInput.addEventListener('input', updateFundFaucetButtonState);
fundRecipientAddressSelect.addEventListener('change', updateFundFaucetButtonState);
startCreateOrgBtn.addEventListener('click', () => {
  optionsSection.classList.add('hidden');
  registerSection.classList.remove('hidden');
  registerBtn.disabled = !connectedAddress || !orgNameInput.value.trim();
});
cancelRegisterBtn.addEventListener('click', () => {
  registerSection.classList.add('hidden');
  hideResult();
  optionsSection.classList.remove('hidden');
});
backToOptionsBtn.addEventListener('click', async () => {
  await loadAvatarState();
});

orgNameInput.addEventListener('input', () => {
  registerBtn.disabled = !connectedAddress || !orgNameInput.value.trim();
});

/* ── Init ─────────────────────────────────────────────────────────── */

showDisconnectedState();
updateWithdrawButtonState();
updateFundFaucetButtonState();
