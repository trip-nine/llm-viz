import React from 'react';
import { VigilConsole } from '@/src/vigil/VigilConsole';

export const metadata = {
    title: 'VIGIL · Model Trust Console',
    description: 'Visual model integrity, behavioral evaluation, and continuous assurance for open-weight AI models.',
};

export default function VigilPage() {
    return <VigilConsole />;
}
