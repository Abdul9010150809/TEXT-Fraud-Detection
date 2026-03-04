import { create } from 'zustand';
import { DEMO_DATASET } from '@/data/demo_dataset';
import { AnalysisResponse } from '@/lib/gemini';

interface FraudStore {
    inputText: string;
    setInputText: (text: string) => void;

    image: string | null; // Base64 image
    setImage: (image: string | null) => void;

    isAnalyzing: boolean;
    setIsAnalyzing: (isAnalyzing: boolean) => void;

    result: AnalysisResponse | null;
    setResult: (result: AnalysisResponse | null) => void;

    demoMode: boolean;
    setDemoMode: (enabled: boolean) => void;

    selectedScenario: string | null;
    setSelectedScenario: (id: string | null) => void;

    language: 'en' | 'hi';
    setLanguage: (lang: 'en' | 'hi') => void;

    fillDemoData: (id: string) => void;
}

export const useFraudStore = create<FraudStore>((set) => ({
    inputText: '',
    setInputText: (text) => set({ inputText: text }),

    image: null,
    setImage: (image) => set({ image }),

    isAnalyzing: false,
    setIsAnalyzing: (isAnalyzing) => set({ isAnalyzing }),

    result: null,
    setResult: (result) => set({ result }),

    demoMode: false,
    setDemoMode: (enabled) => set({ demoMode: enabled }),

    selectedScenario: null,
    setSelectedScenario: (id) => set({ selectedScenario: id }),

    language: 'en',
    setLanguage: (lang) => set({ language: lang }),

    fillDemoData: (id) => {
        const item = DEMO_DATASET.find(d => d.id === id);
        if (item) {
            set({ inputText: item.text, selectedScenario: id, image: null });
        }
    }
}));
