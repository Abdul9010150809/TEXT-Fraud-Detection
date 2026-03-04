import { describe, it, expect } from 'vitest';
import { useFraudStore } from '../store/useFraudStore';

describe('Fraud Store', () => {
    it('should initialize with default values', () => {
        const state = useFraudStore.getState();
        expect(state.inputText).toBe('');
        expect(state.isAnalyzing).toBe(false);
        expect(state.result).toBeNull();
        expect(state.demoMode).toBe(false);
        expect(state.selectedScenario).toBeNull();
    });

    it('should update text input', () => {
        const { setInputText } = useFraudStore.getState();
        setInputText('Hello World');
        expect(useFraudStore.getState().inputText).toBe('Hello World');
    });

    it('should fill demo data correctly', () => {
        const { fillDemoData } = useFraudStore.getState();
        fillDemoData('real-7'); // Urgent Account Block from demo dataset
        const state = useFraudStore.getState();
        expect(state.selectedScenario).toBe('real-7');
        expect(state.inputText.length).toBeGreaterThan(0);
        expect(state.inputText.toLowerCase()).toContain('urg');
    });
});
