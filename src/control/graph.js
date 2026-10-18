/**
 * Static scenario-graph compiler (`compile/` in implementation-design-control
 * §3–§4, architecture §9.4).
 *
 * The control face accepts a bounded, versioned scenario graph whose node
 * vocabulary is `ToolTask` / `AssertTask` / `Fixture` / `Target`. Compilation is
 * pure and happens before any PUT code is loaded. It validates:
 *
 *   - globally unique `node_id` / `test_id` and supported node types;
 *   - resolvable `needs` control edges;
 *   - explicit `inputs.<name> <- outputs.<name>` data edges (never implied by
 *     `needs`), including producer-output binding and JSON-Schema compatibility;
 *   - target ownership and policy-granted permissions (cross-domain data
 *     references rejected);
 *   - per-node and whole-graph declared budgets;
 *   - a deterministic Kahn topological order with `node_id` tie-break.
 *
 * A rejection is a list of machine-readable reason codes; no partial candidate
 * is returned and nothing is executed.
 *
 * @module @deepseek-ai/dsh-plugin-testbed/control/graph
 */
import { CAPABILITY_OBSERVED, inSet } from '../protocol/enums.js';
import { validateSchemaMeta, validateValue } from '../protocol/jsonschema.js';
import { validateToolManifest } from '../protocol/tool-manifest.js';
import { validateRunBudget } from './budget.js';
import { MAX_CASE_ATTEMPTS, MAX_PLAN_CASES, MAX_PLAN_TOTAL_ATTEMPTS } from './limits.js';
/** Supported scenario node types (implementation-design-control §4.1). */
export const SUPPORTED_NODE_TYPES = Object.freeze(['ToolTask', 'AssertTask', 'Fixture', 'Target']);
/** Built-in assertion DSL whitelist (control/assert.js implements these). */
export const SUPPORTED_ASSERTIONS = Object.freeze(['equals', 'contains', 'schema-valid', 'numeric-range', 'finding-count']);
const NODE_FIELDS = Object.freeze({
    ToolTask: ['type', 'node_id', 'test_id', 'classification', 'tool', 'outputs', 'needs', 'retry',
        'dimensions', 'criteria', 'not_applicable_when', 'target_ref', 'domain', 'budget'],
    AssertTask: ['type', 'node_id', 'test_id', 'classification', 'criteria', 'inputs', 'outputs',
        'needs', 'retry', 'dimensions', 'not_applicable_when', 'domain', 'budget'],
    Fixture: ['type', 'node_id', 'fixture_ref', 'outputs', 'needs', 'domain'],
    Target: ['type', 'node_id', 'target_ref', 'domain'],
});
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const FLOATING_TAG = /^(latest|next|canary|main|master|head|snapshot)$/i;
/** @param {unknown} v */
function isPlainObject(v) {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}
/** @param {unknown} v */
function nonEmptyString(v) {
    return typeof v === 'string' && v.length > 0;
}
/** @param {unknown} v */
function uniqueStringArray(v) {
    return Array.isArray(v) && v.length > 0 && v.every(nonEmptyString) && new Set(v).size === v.length;
}
/* ------------------------------------------------------------------------- *
 * Schema compatibility
 * ------------------------------------------------------------------------- */
/** @param {unknown} schema */
function isSchemaObject(schema) {
    return schema === true || schema === false || isPlainObject(schema);
}
/** @param {unknown} value @param {string[]} list */
function typeList(value) {
    if (typeof value === 'string')
        return [value];
    if (Array.isArray(value) && value.every((t) => typeof t === 'string'))
        return value;
    return null;
}
/**
 * Conservative compatibility check for a producer output schema against the
 * consumer input schema. Compatibility means every value the producer declares
 * satisfies the consumer schema. Unknown/absent declarations are not considered
 * incompatible (the runtime value is still schema-checked), but contradictory
 * declarations fail closed.
 *
 * @param {unknown} consumer consumer `input` schema (expected shape)
 * @param {unknown} producer producer `output` schema (guaranteed shape)
 * @returns {boolean}
 */
export function schemasCompatible(consumer, producer) {
    if (consumer === undefined || consumer === null || producer === undefined || producer === null)
        return true;
    if (!isSchemaObject(consumer) || !isSchemaObject(producer))
        return false;
    if (consumer === true || producer === true)
        return true;
    if (producer === false)
        return false;
    if (consumer === false)
        return true; // consumer accepts nothing; no producer value can violate it
    const consumerTypes = typeList(consumer.type);
    const producerTypes = typeList(producer.type);
    if (consumerTypes && producerTypes) {
        if (!producerTypes.every((t) => consumerTypes.includes(t)))
            return false;
    }
    else if (consumerTypes && producerTypes === null && producer.type === undefined) {
        // Consumer constrains the type but the producer does not declare one: not
        // provably compatible at compile time, so fail closed.
        return false;
    }
    // const / enum narrowing
    if (consumer.const !== undefined || Array.isArray(consumer.enum)) {
        const allowed = consumer.const !== undefined ? [consumer.const] : consumer.enum;
        const producerValues = producer.const !== undefined
            ? [producer.const]
            : (Array.isArray(producer.enum) ? producer.enum : null);
        if (producerValues) {
            if (!producerValues.every((v) => allowed.some((a) => jsonEqual(a, v))))
                return false;
        }
    }
    // object shape
    const consumerProps = isPlainObject(consumer.properties) ? consumer.properties : null;
    const producerProps = isPlainObject(producer.properties) ? producer.properties : null;
    if (consumerProps) {
        const consumerRequired = Array.isArray(consumer.required) ? consumer.required : [];
        const producerRequired = Array.isArray(producer.required) ? producer.required : [];
        for (const name of consumerRequired) {
            if (!producerRequired.includes(name)) {
                if (isPlainObject(producerProps) && Object.hasOwn(producerProps, name))
                    continue;
                if (producer.additionalProperties === false)
                    return false;
                // Additional properties are open: presence is not guaranteed.
                return false;
            }
        }
        if (producerProps) {
            for (const [name, consumerSchema] of Object.entries(consumerProps)) {
                if (Object.hasOwn(producerProps, name) && !schemasCompatible(consumerSchema, producerProps[name]))
                    return false;
            }
        }
    }
    // array items
    if (consumer.items !== undefined && producer.items !== undefined) {
        if (!schemasCompatible(consumer.items, producer.items))
            return false;
    }
    // numeric bounds: producer range must be inside the consumer range
    if (typeof consumer.minimum === 'number' && typeof producer.minimum === 'number' &&
        producer.minimum < consumer.minimum)
        return false;
    if (typeof consumer.maximum === 'number' && typeof producer.maximum === 'number' &&
        producer.maximum > consumer.maximum)
        return false;
    if (typeof consumer.minLength === 'number' && typeof producer.minLength === 'number' &&
        producer.minLength < consumer.minLength)
        return false;
    if (typeof consumer.maxLength === 'number' && typeof producer.maxLength === 'number' &&
        producer.maxLength > consumer.maxLength)
        return false;
    if (typeof consumer.minItems === 'number' && typeof producer.minItems === 'number' &&
        producer.minItems < consumer.minItems)
        return false;
    if (typeof consumer.maxItems === 'number' && typeof producer.maxItems === 'number' &&
        producer.maxItems > consumer.maxItems)
        return false;
    return true;
}
/** @param {unknown} a @param {unknown} b */
function jsonEqual(a, b) {
    if (Object.is(a, b))
        return true;
    if (!isPlainObject(a) && !Array.isArray(a))
        return false;
    if (!isPlainObject(b) && !Array.isArray(b))
        return false;
    try {
        return JSON.stringify(a) === JSON.stringify(b);
    }
    catch {
        return false;
    }
}
/* ------------------------------------------------------------------------- *
 * Compilation
 * ------------------------------------------------------------------------- */
/**
 * Compile a scenario graph into a non-removable `PlanCandidate`.
 *
 * @param {{ nodes: object[] }} scenario
 * @param {{ budget?: object, target?: object, authorization?: object }} [options]
 * @returns {{ ok: true, candidate: object } | { ok: false, errors: string[] }}
 */
export function compileScenarioGraph(scenario, options = {}) {
    if (!isPlainObject(scenario) || !Array.isArray(scenario.nodes)) {
        return { ok: false, errors: ['scenario-not-object'] };
    }
    const errors = [];
    const rawNodes = scenario.nodes;
    if (rawNodes.length === 0)
        return { ok: false, errors: ['scenario-nodes-empty'] };
    if (rawNodes.length > MAX_PLAN_CASES) {
        return { ok: false, errors: [`case-count-exceeds-limit:${MAX_PLAN_CASES}`] };
    }
    const nodeById = new Map();
    const testIds = new Set();
    const nodeIds = new Set();
    for (const raw of rawNodes) {
        const nodeId = raw?.node_id;
        if (!isPlainObject(raw) || !nonEmptyString(nodeId)) {
            errors.push('node-id-invalid');
            continue;
        }
        if (nodeIds.has(nodeId))
            errors.push(`duplicate_id:node:${nodeId}`);
        nodeIds.add(nodeId);
        const type = raw.type;
        if (!inSet(SUPPORTED_NODE_TYPES, type)) {
            errors.push(`unsupported_node:${String(type)}:${nodeId}`);
            continue;
        }
        for (const key of Object.keys(raw)) {
            if (!NODE_FIELDS[type].includes(key))
                errors.push(`unsupported_node-field:${nodeId}:${key}`);
        }
        if (type === 'ToolTask' || type === 'AssertTask') {
            if (!nonEmptyString(raw.test_id))
                errors.push(`test-id-invalid:${nodeId}`);
            else {
                if (testIds.has(raw.test_id))
                    errors.push(`duplicate_id:test:${raw.test_id}`);
                testIds.add(raw.test_id);
            }
            if (raw.classification !== 'required' && raw.classification !== 'optional') {
                errors.push(`invalid-classification:${String(raw.test_id)}`);
            }
            const retryError = retryProblem(raw.retry);
            if (retryError)
                errors.push(`${retryError}:${String(raw.test_id)}`);
        }
        let normalized;
        if (type === 'ToolTask')
            normalized = validateToolTask(raw, errors);
        else if (type === 'AssertTask')
            normalized = validateAssertTask(raw, errors);
        else if (type === 'Fixture')
            normalized = validateFixture(raw, errors);
        else
            normalized = validateTargetNode(raw, errors);
        if (normalized)
            nodeById.set(nodeId, normalized);
    }
    // Reference resolution requires all node IDs to be known first.
    for (const node of nodeById.values()) {
        for (const dep of Array.isArray(node.needs) ? node.needs : []) {
            if (!nodeById.has(dep))
                errors.push(`reference_unresolved:${node.node_id}->${dep}`);
        }
    }
    const dataEdges = [];
    for (const node of nodeById.values()) {
        if (node.inputs === undefined)
            continue;
        for (const [name, binding] of Object.entries(node.inputs)) {
            if (!isPlainObject(binding) || !nonEmptyString(binding.from) || !nonEmptyString(binding.output)) {
                errors.push(`unbound_input:${node.node_id}:${name}`);
                continue;
            }
            const producer = nodeById.get(binding.from);
            if (!producer) {
                errors.push(`reference_unresolved:${node.node_id}->${binding.from}`);
                continue;
            }
            const outputs = isPlainObject(producer.outputs) ? producer.outputs : {};
            if (!Object.hasOwn(outputs, binding.output)) {
                errors.push(`unbound_input:${node.node_id}:${name}`);
                continue;
            }
            if (binding.schema !== undefined) {
                if (!isSchemaObject(binding.schema))
                    errors.push(`schema_incompatible:${node.node_id}:${name}`);
                else if (!schemasCompatible(binding.schema, outputs[binding.output])) {
                    errors.push(`schema_incompatible:${node.node_id}:${name}`);
                }
            }
            if (typeof producer.domain === 'string' && typeof node.domain === 'string' && producer.domain !== node.domain) {
                errors.push(`cross_domain_ref:${producer.node_id}->${node.node_id}`);
            }
            dataEdges.push({ from: producer.node_id, output: binding.output, to: node.node_id, input: name });
        }
    }
    const nodes = [...nodeById.values()];
    validateAuthorization(nodes, options, errors);
    validateGraphBudget(nodes, options, errors);
    const topoOrder = stableTopo(nodes, dataEdges);
    if (topoOrder === null) {
        errors.push('cycle');
    }
    if (errors.length > 0)
        return { ok: false, errors };
    const orderedNodes = topoOrder.map((id) => nodeById.get(id));
    const testNodes = orderedNodes.filter((node) => node.type === 'ToolTask' || node.type === 'AssertTask');
    const candidate = {
        nodeIds: orderedNodes.map((node) => node.node_id),
        nodeById: Object.fromEntries(orderedNodes.map((node) => [node.node_id, node])),
        nodes: orderedNodes,
        testIds: testNodes.map((node) => node.test_id),
        baselineTestIds: testNodes.map((node) => node.test_id),
        requiredTestIds: testNodes.filter((node) => node.classification === 'required').map((node) => node.test_id),
        topoOrder: orderedNodes.map((node) => node.node_id),
        testOrder: testNodes.map((node) => node.test_id),
        cases: testNodes,
        dataEdges,
    };
    return { ok: true, candidate };
}
/**
 * Validate a scenario graph without exposing the compiled candidate. The full
 * compiler is authoritative; this is a convenient fail-closed admission check.
 *
 * @param {{ nodes: object[] }} scenario
 * @param {{ budget?: object, target?: object, authorization?: object }} [options]
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function validateScenario(scenario, options = {}) {
    const result = compileScenarioGraph(scenario, options);
    return result.ok ? { ok: true, errors: [] } : { ok: false, errors: result.errors };
}
/** @param {object} raw @param {string[]} errors */
function validateToolTask(raw, errors) {
    const node = { ...raw };
    if (!isPlainObject(raw.tool)) {
        errors.push(`tool-manifest-invalid:${raw.node_id}`);
        return node;
    }
    const manifest = raw.tool.manifest;
    const checked = validateToolManifest(manifest);
    if (!checked.ok) {
        errors.push(`tool-manifest-invalid:${raw.node_id}:${checked.errors[0] ?? 'unknown'}`);
    }
    else {
        const inputCheck = validateValue(raw.tool.input, manifest.input_schema);
        if (!inputCheck.ok)
            errors.push(`tool-input-schema-invalid:${raw.node_id}:${inputCheck.errors[0] ?? 'unknown'}`);
    }
    if (!isPlainObject(raw.tool.input))
        errors.push(`tool-input-schema-invalid:${raw.node_id}:input-not-object`);
    if (raw.outputs !== undefined) {
        if (!isPlainObject(raw.outputs) || Object.keys(raw.outputs).length === 0) {
            errors.push(`output-schema-invalid:${raw.node_id}`);
        }
        else {
            for (const [name, schema] of Object.entries(raw.outputs)) {
                const meta = validateSchemaMeta(schema);
                if (!meta.ok)
                    errors.push(`output-schema-invalid:${raw.node_id}:${name}:${meta.errors[0] ?? 'invalid'}`);
            }
        }
    }
    else if (isPlainObject(manifest) && manifest.observation_schema !== undefined) {
        node.outputs = { observation: manifest.observation_schema };
    }
    else {
        node.outputs = {};
    }
    if (raw.target_ref !== undefined)
        validateTargetRef(raw.target_ref, raw.node_id, errors);
    if (raw.criteria !== undefined)
        validateCriteria(raw.criteria, raw.node_id, errors);
    validateNotApplicablePredicate(raw.not_applicable_when, raw.node_id, errors);
    return node;
}
/** @param {object} raw @param {string[]} errors */
function validateAssertTask(raw, errors) {
    const node = { ...raw };
    if (!isPlainObject(raw.criteria)) {
        errors.push(`missing-criteria:${raw.node_id}`);
    }
    else {
        validateCriteria(raw.criteria, raw.node_id, errors);
    }
    if (!isPlainObject(raw.inputs) || Object.keys(raw.inputs).length === 0) {
        errors.push(`unbound_input:${raw.node_id}:value`);
    }
    if (raw.outputs !== undefined) {
        if (!isPlainObject(raw.outputs))
            errors.push(`output-schema-invalid:${raw.node_id}`);
        else {
            for (const [name, schema] of Object.entries(raw.outputs)) {
                const meta = validateSchemaMeta(schema);
                if (!meta.ok)
                    errors.push(`output-schema-invalid:${raw.node_id}:${name}:${meta.errors[0] ?? 'invalid'}`);
            }
        }
    }
    validateNotApplicablePredicate(raw.not_applicable_when, raw.node_id, errors);
    return node;
}
/** @param {object} raw @param {string[]} errors */
function validateFixture(raw, errors) {
    const node = { ...raw };
    const ref = raw.fixture_ref;
    if (!isPlainObject(ref) || !nonEmptyString(ref.id) || !nonEmptyString(ref.version) ||
        typeof ref.digest !== 'string' || !SHA256.test(ref.digest)) {
        errors.push(`artifact_unresolved:${raw.node_id}`);
    }
    else {
        if (!pinnedVersion(ref.version))
            errors.push(`floating_ref:${raw.node_id}`);
    }
    if (raw.outputs !== undefined && !isPlainObject(raw.outputs)) {
        errors.push(`output-schema-invalid:${raw.node_id}`);
    }
    return node;
}
/** @param {object} raw @param {string[]} errors */
function validateTargetNode(raw, errors) {
    const node = { ...raw };
    validateTargetRef(raw.target_ref, raw.node_id, errors);
    return node;
}
/** @param {unknown} criteria @param {string} nodeId @param {string[]} errors */
function validateCriteria(criteria, nodeId, errors) {
    if (!isPlainObject(criteria) || !inSet(SUPPORTED_ASSERTIONS, criteria.assert)) {
        errors.push(`unsupported_assertion:${nodeId}:${String(criteria?.assert)}`);
    }
}
/** @param {unknown} predicate @param {string} nodeId @param {string[]} errors */
function validateNotApplicablePredicate(predicate, nodeId, errors) {
    if (predicate === undefined)
        return;
    if (!isPlainObject(predicate) || !inSet(CAPABILITY_OBSERVED, predicate.observed) ||
        (predicate.verification !== undefined && predicate.verification !== 'corroborated')) {
        errors.push(`not-applicable-predicate-missing-or-invalid:${nodeId}`);
    }
}
/** @param {unknown} ref @param {string} nodeId @param {string[]} errors */
function validateTargetRef(ref, nodeId, errors) {
    if (!isPlainObject(ref) || !nonEmptyString(ref.kind) ||
        typeof ref.owner_put_digest !== 'string' || !SHA256.test(ref.owner_put_digest)) {
        errors.push(`unauthorized_target:${nodeId}`);
    }
}
/** @param {unknown} version */
function pinnedVersion(version) {
    if (!nonEmptyString(version))
        return false;
    if (FLOATING_TAG.test(version))
        return false;
    if (/^[\^~<>=*]|[xX*]$/.test(version))
        return false;
    return true;
}
/** @param {unknown} retry @returns {string|null} */
function retryProblem(retry) {
    if (retry === undefined || retry === null)
        return null;
    if (!isPlainObject(retry))
        return 'retry-invalid';
    if (!Number.isSafeInteger(retry.max_attempts) || retry.max_attempts < 1)
        return 'retry-max-attempts-invalid';
    if (retry.max_attempts > MAX_CASE_ATTEMPTS)
        return 'retry-max-attempts-exceeds-limit';
    if (Object.hasOwn(retry, 'safe') && typeof retry.safe !== 'boolean')
        return 'retry-safe-invalid';
    return null;
}
/** @param {object[]} nodes @param {object} options @param {string[]} errors */
function validateAuthorization(nodes, options, errors) {
    const authorization = options.authorization;
    const trustedTarget = isPlainObject(options.target)
        ? options.target
        : (isPlainObject(authorization?.target) ? authorization.target : null);
    const trustedPutDigest = typeof authorization?.put_digest === 'string'
        ? authorization.put_digest
        : (trustedTarget?.put_digest ?? null);
    const grants = authorization?.granted_permissions;
    if (grants !== undefined) {
        if (!isPlainObject(grants)) {
            errors.push('permission_denied:authorization-invalid');
        }
        else {
            for (const node of nodes) {
                if (node.type !== 'ToolTask' || !isPlainObject(node.tool?.manifest?.permissions))
                    continue;
                for (const [key, requested] of Object.entries(node.tool.manifest.permissions)) {
                    if (!Array.isArray(requested) || requested.length === 0)
                        continue;
                    const granted = grants[key];
                    if (!Array.isArray(granted)) {
                        errors.push(`permission_denied:${node.node_id}:${key}`);
                        continue;
                    }
                    for (const value of requested) {
                        if (!granted.includes(value))
                            errors.push(`permission_denied:${node.node_id}:${key}:${value}`);
                    }
                }
            }
        }
    }
    for (const node of nodes) {
        const ref = node.type === 'ToolTask' || node.type === 'Target' ? node.target_ref : null;
        if (!ref || !trustedTarget)
            continue;
        if (nonEmptyString(trustedTarget.kind) && ref.kind !== trustedTarget.kind) {
            errors.push(`unauthorized_target:${node.node_id}`);
        }
        if (typeof trustedTarget.put_digest === 'string' && ref.owner_put_digest !== trustedTarget.put_digest) {
            errors.push(`ownership_mismatch:${node.node_id}`);
        }
    }
    if (trustedPutDigest !== null) {
        for (const node of nodes) {
            if (node.target_ref && node.target_ref.owner_put_digest !== trustedPutDigest) {
                errors.push(`ownership_mismatch:${node.node_id}`);
            }
        }
    }
}
/** @param {object[]} nodes @param {object} options @param {string[]} errors */
function validateGraphBudget(nodes, options, errors) {
    if (options.budget === undefined || options.budget === null)
        return;
    const checked = validateRunBudget(options.budget);
    if (!checked.ok) {
        for (const error of checked.errors)
            errors.push(`budget-invalid:${error}`);
        return;
    }
    const budget = checked.budget;
    const testNodes = nodes.filter((node) => node.type === 'ToolTask' || node.type === 'AssertTask');
    const declaredAttempts = testNodes.reduce((sum, node) => sum + (node.retry?.max_attempts ?? 1), 0);
    if (declaredAttempts > budget.max_total_attempts)
        errors.push('budget_exceeded:attempts');
    let timeoutMs = 0;
    let cpuMs = 0;
    let outputBytes = 0;
    for (const node of nodes) {
        if (node.type !== 'ToolTask')
            continue;
        const limits = node.tool?.manifest?.limits;
        if (!isPlainObject(limits))
            continue;
        timeoutMs += limits.timeout_ms ?? 0;
        cpuMs += limits.cpu_ms ?? 0;
        outputBytes += limits.output_bytes ?? 0;
    }
    if (timeoutMs > budget.max_total_time_ms)
        errors.push('budget_exceeded:timeout_ms');
    if (cpuMs > budget.max_total_cpu_ms)
        errors.push('budget_exceeded:cpu_ms');
    if (outputBytes > budget.max_total_output_bytes)
        errors.push('budget_exceeded:output_bytes');
    if (declaredAttempts > MAX_PLAN_TOTAL_ATTEMPTS)
        errors.push(`candidate-attempt-total-exceeds-limit:${MAX_PLAN_TOTAL_ATTEMPTS}`);
}
/**
 * Deterministic Kahn topological sort over `needs` + explicit data edges.
 * Ready nodes are ordered by lexicographic `node_id`.
 * @param {object[]} nodes
 * @param {{from:string,to:string}[]} dataEdges
 * @returns {string[]|null} topo order or null on cycle
 */
function stableTopo(nodes, dataEdges) {
    const inDegree = new Map();
    const successors = new Map();
    for (const node of nodes) {
        inDegree.set(node.node_id, 0);
        successors.set(node.node_id, []);
    }
    const dependencies = new Map();
    for (const node of nodes) {
        const deps = new Set(Array.isArray(node.needs) ? node.needs : []);
        for (const edge of dataEdges)
            if (edge.to === node.node_id)
                deps.add(edge.from);
        dependencies.set(node.node_id, deps);
    }
    for (const node of nodes) {
        for (const dep of dependencies.get(node.node_id)) {
            if (!inDegree.has(dep))
                continue;
            inDegree.set(node.node_id, inDegree.get(node.node_id) + 1);
            successors.get(dep).push(node.node_id);
        }
    }
    const ready = [];
    for (const node of nodes)
        if (inDegree.get(node.node_id) === 0)
            ready.push(node.node_id);
    ready.sort();
    const order = [];
    while (ready.length > 0) {
        const id = ready.shift();
        order.push(id);
        for (const succ of successors.get(id)) {
            const degree = inDegree.get(succ) - 1;
            inDegree.set(succ, degree);
            if (degree === 0) {
                ready.push(succ);
                ready.sort();
            }
        }
    }
    return order.length === nodes.length ? order : null;
}
