import { FeedbackStorage } from './storage';
import { FeedbackCollector, initializeStorage } from './collector';
import { PromptEnhancer } from './enhancer';
import type { 
  FeedbackEvent, 
  FeedbackQuery, 
  FeedbackStats, 
  FeedbackType,
  FeedbackSentiment,
  ActionTaken,
  PromptEnhancementContext,
  Reviewer,
  FeedbackContext,
  Modification
} from './types';

// Create singleton instances
const feedbackStorage = new FeedbackStorage();
initializeStorage(feedbackStorage);
const feedbackCollector = new FeedbackCollector(feedbackStorage);
const promptEnhancer = new PromptEnhancer();

export {
  feedbackStorage,
  feedbackCollector,
  promptEnhancer,
  FeedbackStorage,
  FeedbackCollector,
  PromptEnhancer,
  FeedbackEvent,
  FeedbackQuery,
  FeedbackStats,
  FeedbackType,
  FeedbackSentiment,
  ActionTaken,
  PromptEnhancementContext,
  Reviewer,
  FeedbackContext,
  Modification
};