import React from 'react';
import { LayerView } from '@/src/llm/LayerView';

export const metadata = {
    title: 'VIGIL Model Map',
    description: 'Interactive transformer topology.',
};

export default function VigilModelMapPage() {
    return <>
        <LayerView />
        <div id="portal-container" />
    </>;
}
