import { Injectable, InternalServerErrorException, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { WebDataDto } from '../common/dtos/web-data.dto';
import { chromium, Browser, BrowserContext, Page } from 'playwright';
import { WebIdentifierResponse, WebIdentifierResponseCategories, WebIdentifierTypeResponse } from './dto/web-identifier-response.interface';

@Injectable()
export class WebIdentifierService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger('WEB-IDENTIFIER-SERVICE');
  private readonly min_confidence: number = 50;
  private readonly category_groups: { type: WebIdentifierTypeResponse; ids: number[] }[] = [
    { type: WebIdentifierTypeResponse.DEVELOPMENT_DATABASE, ids: [27, 47, 34, 1] },
    { type: WebIdentifierTypeResponse.FRAMEWORKS_LIBRARIES, ids: [18, 12, 59, 57] },
    { type: WebIdentifierTypeResponse.SERVER_SECURITY, ids: [22, 16, 70, 62] }
  ];
  private readonly categoryTypeMap: Map<number, WebIdentifierTypeResponse> = new Map<number, WebIdentifierTypeResponse>();
  private readonly categoryOrderMap: Map<number, number> = new Map<number, number>();
  private wappalyzerInstance: any;
  private browser!: Browser;

  constructor() {
    let index: number = 0;
    for (const group of this.category_groups) {
      for (const id of group.ids) {
        this.categoryTypeMap.set(id, group.type);
        this.categoryOrderMap.set(id, index++);
      }
    }
  }

  async onModuleInit() {
    const Wappalyzer = require('wapalyzer');
    this.browser = await chromium.launch({ headless: true });
    this.wappalyzerInstance = new Wappalyzer();
    await this.wappalyzerInstance.init();
  }

  async onModuleDestroy() {
    if (this.wappalyzerInstance) {
      await this.wappalyzerInstance.destroy();
    }
    if (this.browser) {
      await this.browser.close();
    }
  }

  async getWebIdentifier(webDataDto: WebDataDto): Promise<WebIdentifierResponse[]> {
    let site: any;
    try {
      site = await this.wappalyzerInstance.open(webDataDto.web_url);
      const results: any = await site.analyze();
      let response: WebIdentifierResponse[] = this.mapToWebIdentifierResponse(results.technologies);
      const hasLanguage: boolean = response.some((item) => item.categories.some((cat) => cat.id === 27));
      const hasFramework: boolean = response.some((item) => item.categories.some((cat) => cat.id === 18));
      if (!hasLanguage || !hasFramework) {
        response = await this.fillMissingLanguageAndFramework(webDataDto.web_url, response, hasLanguage, hasFramework);
      }
      return response.sort((a, b) => a.type - b.type);
    } catch (error: any) {
      this.logger.error(`Error crítico: ${error.stack}`);
      throw new InternalServerErrorException(`Se produjo un error al consultar las características de la web: ${error}`);
    } finally {
      if (site) {
        try {
          await site.destroy();
        } catch (cleanupError: any) {
          this.logger.warn(`No se pudo liberar el 'site' de Wappalyzer: ${cleanupError}`);
        }
      }
    }
  }

  private mapToWebIdentifierResponse(technologies: any[]): WebIdentifierResponse[] {
    const response: WebIdentifierResponse[] = [];
    for (const tech of technologies ?? []) {
      if (typeof tech.confidence !== 'number' || tech.confidence < this.min_confidence) {
        continue;
      }
      const categories: WebIdentifierResponseCategories[] = this.filterAndSortCategories(tech.categories);
      if (categories.length === 0) continue;
      const type: WebIdentifierTypeResponse | null = this.resolveType(categories);
      if (type === null) continue;
      response.push({
        name: tech.name,
        type,
        confidence: tech.confidence,
        version: tech.version ?? null,
        website: tech.website ?? null,
        categories,
      });
    }
    return response;
  }

  private filterAndSortCategories(categories: any[]): WebIdentifierResponseCategories[] {
    return (categories ?? [])
      .filter((cat) => this.categoryOrderMap.has(cat.id))
      .sort((a, b) => (this.categoryOrderMap.get(a.id) ?? 0) - (this.categoryOrderMap.get(b.id) ?? 0))
      .map((cat) => ({ id: cat.id, name: cat.name }));
  }

  private resolveType(categories: WebIdentifierResponseCategories[]): WebIdentifierTypeResponse | null {
    for (const cat of categories) {
      const type: WebIdentifierTypeResponse | undefined = this.categoryTypeMap.get(cat.id);
      if (type !== undefined) return type;
    }
    return null;
  }

  private async fillMissingLanguageAndFramework(webUrl: string, response: WebIdentifierResponse[], hasLanguage: boolean, hasFramework: boolean): Promise<WebIdentifierResponse[]> {
    const programming_language_category: WebIdentifierResponseCategories = { id: 27, name: 'Programming languages' };
    const web_framework_category: WebIdentifierResponseCategories = { id: 18, name: 'Web frameworks' };
    try {
      const { framework, language } = await this.detectFrameworkAndLanguage(webUrl);
      if (!hasLanguage) {
        response.push({
          name: language,
          type: WebIdentifierTypeResponse.DEVELOPMENT_DATABASE,
          confidence: 100,
          version: null,
          website: null,
          categories: [programming_language_category]
        });
      }
      if (!hasFramework) {
        response.push({
          name: framework,
          type: WebIdentifierTypeResponse.FRAMEWORKS_LIBRARIES,
          confidence: 100,
          version: null,
          website: null,
          categories: [web_framework_category]
        });
      }
    } catch (error: any) {
      this.logger.warn(`No se pudo completar framework/lenguaje vía DetectFrameworkAndLanguage: ${error}`);
    }
    return response;
  }

  async detectFrameworkAndLanguage(webUrl: string): Promise<{ framework: string; language: string }> {
    const context: BrowserContext = await this.browser.newContext({ ignoreHTTPSErrors: true });
    const page: Page = await context.newPage();
    try {
      await page.route('**/*.{png,jpg,jpeg,gif,svg,woff,woff2,css}', (route) => route.abort());
      const response = await page.goto(webUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
      if (!response) {
        throw new Error('El servidor no devolvió una respuesta válida');
      }
      return await page.evaluate(() => {
        const htmlText: string = document.documentElement.outerHTML;
        const allElements: Element[] = Array.from(document.querySelectorAll('*'));
        // --- DETECCIÓN DE TECNOLOGIA ---
        const hasReactFiber: boolean = allElements.some((el) =>
          Object.keys(el).some(
            (key) => key.startsWith('__reactFiber$') || key.startsWith('__reactContainer$') || key.startsWith('__reactProps$'),
          )
        );
        const hasGlobalReactState: boolean =
          !!(window as any).React ||
          !!(window as any).__REACT_DEVTOOLS_GLOBAL_HOOK__?.renderers?.size ||
          htmlText.includes('react-application') ||
          !!document.querySelector('script[id="__NEXT_DATA__"]');
        const isReact: boolean = hasReactFiber || hasGlobalReactState;
        const isNext: boolean = htmlText.includes('__NEXT_DATA__');
        const isVue: boolean =
          !!(window as any).__VUE__ ||
          !!(window as any).Vue ||
          allElements.some((el) => Object.keys(el).some((k) => k.startsWith('__vue_app__') || k.startsWith('__vue__'))) ||
          htmlText.includes('data-v-') ||
          htmlText.includes('__NUXT__');
        const isNuxt: boolean = htmlText.includes('__NUXT__');
        const isAngular: boolean =
          !!document.querySelector('[ng-version]') ||
          htmlText.includes('_nghost-') ||
          htmlText.includes('_ngcontent-') ||
          !!(window as any).ng;
        const isSvelte: boolean = htmlText.includes('svelte-') || !!(window as any).__svelte;
        const isAspNet: boolean = htmlText.includes('__VIEWSTATE') || htmlText.includes('aspnet') || htmlText.includes('WebResource.axd');
        const isLaravel: boolean = htmlText.includes('laravel_session') || htmlText.includes('XSRF-TOKEN');
        // --- DETECCIÓN DE FRAMEWORK ---
        let framework: string = 'HTML Estático / Desconocido';
        if (isNext) framework = 'Next.js (React)';
        else if (isReact) framework = 'React';
        else if (isNuxt) framework = 'Nuxt.js (Vue)';
        else if (isVue) framework = 'Vue.js';
        else if (isAngular) framework = 'Angular';
        else if (isSvelte) framework = 'Svelte / SvelteKit';
        else if (isAspNet) framework = 'ASP.NET';
        else if (isLaravel) framework = 'Laravel';
        // --- DETECCIÓN DE LENGUAJE ---
        const isTypeScript: boolean =
          isAngular ||
          !!(window as any).__webpack_require__ ||
          htmlText.includes('tslib') ||
          htmlText.includes('.ts') ||
          htmlText.includes('__ts');
        let language: string = 'JavaScript';
        if (isAspNet) {
          language = 'C# (.NET)';
        } else if (isLaravel || htmlText.includes('.php')) {
          language = 'PHP';
        } else if (htmlText.includes('django') || htmlText.includes('csrfmiddlewaretoken')) {
          language = 'Python (Django)';
        } else if (htmlText.includes('rails') || htmlText.includes('authenticity_token')) {
          language = 'Ruby (Ruby on Rails)';
        } else if (isTypeScript) {
          language = 'TypeScript';
        }
        return { framework, language };
      });
    } finally {
      await page.close();
      await context.close();
    }
  }
}
